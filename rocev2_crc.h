#ifndef ROCEV2_CRC_H
#define ROCEV2_CRC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 计算 RoCEv2 iCRC。
 *
 * @param packet    指向完整以太网帧（包含以太网头，可带 VLAN tag）。
 * @param len       从以太网头到载荷结尾（不含 iCRC 字段）的字节长度。
 * @param out_icrc  输出 32 位 iCRC（主机字节序）。
 * @return 0 成功，非 0 失败。
 */
int rocev2_icrc(const uint8_t *packet, size_t len, uint32_t *out_icrc);

#ifdef __cplusplus
}
#endif

#endif /* ROCEV2_CRC_H */
