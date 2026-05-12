# RoCEv2 fault injection design

## 中文落地建议

如果目标是“性能要求最高”，建议把损伤注入拆成**规则更新慢路径**和
**收发包热路径**两套完全不同的机制：

- pytest 只通过 QMP/socket 下发字符串规则；QEMU 在规则更新时完成解析、校验、
  常量折叠、opcode 枚举翻译、prefilter 提取和 bytecode 生成。
- TX 出口/RX 入口绝不解析字符串，绝不调用 Python，绝不获取全局锁，绝不为了
  `delay` 同步睡眠。
- 没有规则时，热路径只做一次 ruleset 指针读取和一次 `likely()` 分支，然后直接
  返回 `PASS`。这是最重要的性能边界。
- 有规则时，每个包只解析一次 RoCEv2/BTH 元数据，得到 `qpn/opcode/psn` 等字段，
  先走 QPN/opcode/modulo 等 cheap prefilter，再进入 bytecode evaluator。
- `delay(500us)` 的语义应是“偷走 packet，放入 timer-backed delayed queue，到期后
  重新投递”，而不是在 TX/RX hook 里 sleep。

推荐第一版只支持最小但高价值的语法：

```text
where:  qpn == 1 && ((psn % 100) == 0 || opcode == read)
action: delay(500us)
```

注意：`psn & 100 == 0` 在 C-like 表达式中表示**按位与**，不是“每 100 个
包”。如果测试想表达每 100 个 PSN 命中一次，应使用 `(psn % 100) == 0`。

最低风险的落地顺序是：先实现 QMP add/list/clear 和 `mark/drop`，用 counters 验证
谓词匹配正确；再实现非阻塞 `delay`；最后根据 benchmark 决定是否启用 QPN hash
或 timing wheel。


## Goals

This design targets a QEMU-emulated RoCEv2 PCIe NIC whose packet fast path has a
TX egress hook and an RX ingress hook. The feature is intended for user-space
pytest tests that install, query, and clear temporary fault rules for each test
case while keeping the normal no-fault packet path as close to zero-cost as
possible.

Primary goals:

- Expressive test API: multiple rules, boolean predicates over RoCEv2 fields, and
  actions such as delay.
- Safe lifecycle: add, replace, list, enable/disable, and clear rules without
  restarting the guest.
- Deterministic tests: rule hit counters and rule generation numbers allow pytest
  to assert that the intended packets were affected.
- Highest performance: no string parsing, allocation, locking, sleeping, or QMP
  work in the packet hot path.

## Recommendation

Use a two-plane architecture:

1. **Control plane**: pytest sends rule text to QEMU through QMP. QEMU parses and
   compiles rules only when rules are changed.
2. **Data plane**: TX/RX hooks evaluate a precompiled immutable ruleset through a
   single RCU-protected pointer. If no rules are installed, the hook returns after
   one predictable branch.

Do not parse the user expression in the TX/RX hook. Do not call into Python or a
monitor command from the hook. Do not sleep in the hook for `delay`; enqueue the
packet on a timer-backed delayed queue.

## User-facing pytest shape

A thin pytest helper can hide QMP details and keep tests readable:

```python
with roce_faults(qmp) as faults:
    rule_id = faults.add(
        direction="tx",
        where="qpn == 1 && ((psn % 100) == 0 || opcode == 'read')",
        action="delay(500us)",
        priority=10,
        limit=1000,
    )
    # run traffic
    assert faults.get(rule_id)["hits"] > 0
# context manager clears all rules it created
```

Recommended QMP commands:

- `x-roce-fi-add`: add a rule and return `{ "id": N, "generation": G }`.
- `x-roce-fi-del`: delete one rule by ID.
- `x-roce-fi-clear`: clear all rules, optionally by device and direction.
- `x-roce-fi-list`: return active rules, counters, and generation.
- `x-roce-fi-set-enabled`: enable or disable fault injection globally.

Use an `x-` prefix until the QMP schema is stable.

## Rule semantics

A rule is an immutable object:

```c
struct roce_fi_rule {
    uint64_t id;
    uint32_t priority;
    uint32_t flags;
    enum roce_fi_dir dir;
    enum roce_fi_action action;
    uint64_t action_arg_ns;
    uint64_t limit;
    QEMUAtomic uint64_t hits;
    QEMUAtomic uint64_t applied;
    struct roce_fi_pred pred;
};
```

Rules are evaluated by ascending priority, then ID. Stop at the first matching
rule unless a later `continue` flag is explicitly added. First-match semantics are
faster and easier to reason about than applying every matching rule.

Supported predicate fields should be small and fixed at first:

- `dir`: `tx` or `rx`.
- `qpn`: destination QP from BTH.
- `psn`: packet sequence number from BTH.
- `opcode`: BTH opcode, with symbolic names such as `read`, `write`, `send`, and
  `ack` translated at compile time.
- `pkey`, `dqpn`, `ecn`, `src_ip`, `dst_ip`, `src_port`, and `dst_port` can be
  added as needed, but every added field should be parsed once into packet
  metadata rather than repeatedly by each rule.

Use C-like operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`, `&`,
`|`, `^`, `%`, `+`, `-`, `*`, parentheses, decimal/hex integer literals, and
quoted enums. Treat `psn & 100 == 0` as bitwise AND; tests that want every 100th
packet should write `(psn % 100) == 0`.

## Data-plane packet metadata

Parse packet headers once per packet into a compact stack object:

```c
struct roce_fi_pkt_meta {
    uint32_t qpn;
    uint32_t psn;
    uint8_t opcode;
    uint8_t valid_mask;
    bool is_rocev2;
};
```

The TX/RX hook should look like this:

```c
static inline enum roce_fi_result roce_fi_apply(RoceDev *dev,
                                                enum roce_fi_dir dir,
                                                Packet *pkt)
{
    struct roce_fi_ruleset *rs = qatomic_rcu_read(&dev->fi.ruleset);

    if (likely(!rs || !rs->enabled || rs->nr_rules == 0)) {
        return ROCE_FI_PASS;
    }

    return roce_fi_apply_slow(dev, rs, dir, pkt);
}
```

Only the slow path should parse RoCEv2/BTH metadata. This makes the common case
with no installed rules pay one pointer load and one branch.

## Predicate compilation for performance

Compile rule text into one of these forms outside the hot path:

1. **Fastest portable option**: AST nodes compiled to a compact bytecode with a
   stackless interpreter. Use fixed-size instructions and direct `switch` dispatch.
2. **Even faster for common rules**: specialize simple predicates into a small set
   of native C evaluators, such as `qpn == constant`, `qpn == constant && opcode ==
   constant`, or `qpn == constant && psn % N == K`.
3. **Optional future optimization**: generate TCG or host JIT code only if
   benchmarks prove bytecode dispatch is insufficient. This adds portability and
   security complexity, so it should not be the first implementation.

Recommended hybrid:

- Store every rule as bytecode.
- During compile, classify simple predicates and set prefilter fields.
- In the hot path, run prefilters before the bytecode evaluator.

Example prefilter fields:

```c
struct roce_fi_prefilter {
    uint32_t qpn_value;
    uint32_t qpn_mask;
    uint8_t opcode_value;
    uint8_t opcode_mask;
    bool has_psn_mod;
    uint32_t psn_mod_divisor;
    uint32_t psn_mod_remainder;
};
```

For the example rule, the compiler emits a QPN prefilter and a PSN modulo
prefilter for the left branch, then bytecode for the remaining boolean expression.

## Multiple rules and lookup strategy

Use a global immutable ruleset per device:

```c
struct roce_fi_ruleset {
    bool enabled;
    uint64_t generation;
    size_t nr_rules;
    struct roce_fi_rule *rules[];
};
```

For best performance when rule counts grow, additionally build indexes at compile
time:

- `qpn_exact_hash`: maps QPN to a compact array of candidate rule pointers.
- `opcode_buckets[256]`: optional buckets for opcode-only rules.
- `wildcard_rules`: rules without a cheap exact prefilter.

The apply path should first get candidates from the QPN hash if the packet has a
QPN, append wildcard rules, and evaluate only those candidates in priority order.
For the expected pytest use case with a small number of rules, a sorted array scan
is likely faster than a complex index; keep the index optional and benchmark both.

## Delay action

Never block the TX/RX hook. `delay(500us)` should:

1. Take ownership or a reference to the packet/buffer.
2. Push it into a per-direction min-heap or timer-wheel keyed by release time.
3. Arm a QEMU timer for the earliest release time.
4. Return `ROCE_FI_STOLEN` so the normal path does not transmit or deliver it.
5. The timer callback releases due packets into the existing TX/RX continuation.

Use nanoseconds internally and parse user units such as `ns`, `us`, `ms`, and `s`.
For high packet rates with many delayed packets, prefer a hierarchical timing
wheel with per-slot queues over a binary heap. For pytest-scale traffic, a heap is
simpler and usually sufficient.

## Rule updates and concurrency

Rule updates should be copy-on-write:

1. QMP command parses and validates the new rule.
2. Allocate a new ruleset and copy existing rule pointers.
3. Insert/delete/clear the desired rules.
4. Sort and build optional indexes.
5. Atomically publish the new ruleset with RCU.
6. Free the old ruleset after an RCU grace period.

Counters should be atomics in per-rule objects so they survive ruleset replacement
until the rule is deleted. For extremely high packet rates, use per-vCPU or
per-queue counters and aggregate on `list` to avoid a shared atomic increment on
every matching packet.

## Actions

Start with the smallest action set required by tests:

- `delay(duration)`: delayed delivery/transmit.
- `drop`: consume the packet.
- `corrupt(field_or_offset, value, mask)`: mutate selected bytes.
- `duplicate(count, spacing)`: clone packets, optionally spacing clones.
- `mark(name_or_value)`: counter-only action for tracing and assertions.

Make actions explicit about ownership:

- `PASS`: packet continues normally.
- `DROP`: hook consumed packet.
- `STOLEN`: hook queued packet and will release later.
- `MODIFIED`: packet continues with mutations applied.

## Observability

Expose counters per rule:

- `hits`: predicate matched.
- `applied`: action successfully applied.
- `limited`: predicate matched but rule limit was exhausted.
- `errors`: action failed, for example because a packet clone failed.
- `last_error`: short diagnostic string.

Add tracepoints around rule match and action application, but keep tracepoints
disabled by default.

## Validation and safety

- Reject expressions above a maximum length.
- Limit AST nodes, bytecode instructions, rules per device, and delayed queue
  depth.
- Reject division or modulo by zero at compile time when possible and at runtime
  otherwise.
- Validate action arguments and require explicit units for delay.
- Keep experimental commands device-scoped so parallel tests do not collide.
- Provide a pytest fixture that clears rules in `finally`.

## Suggested implementation order

1. Add QMP schema and an empty fast-path hook that is disabled by default.
2. Implement `clear`, `list`, and copy-on-write ruleset publication.
3. Add a parser for simple comparisons and `&&`/`||`.
4. Add RoCEv2 metadata extraction for BTH `opcode`, `qpn`, and `psn`.
5. Implement `drop` and `mark`; use counters to validate predicates.
6. Implement non-blocking `delay` with a QEMU timer and delayed queue.
7. Add prefilters and optional QPN indexing after benchmarks show the baseline.
8. Add pytest helpers and tests that install rules per test and verify cleanup.

## Performance checklist

- No rules installed: one RCU pointer load and one likely branch.
- Rules installed: parse packet metadata exactly once.
- No locks in the packet hook; use RCU for ruleset reads.
- No heap allocation in the packet hook except actions that inherently need packet
  ownership or cloning.
- No string comparisons in the packet hook; enums and symbols are numeric.
- Prefer per-queue delayed structures to reduce contention.
- Benchmark three cases: no rules, one QPN-specific rule, and many wildcard rules.
