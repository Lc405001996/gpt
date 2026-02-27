#ifndef ROCEV2_CRC_H
#define ROCEV2_CRC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 计算 RoCEv2 iCRC（不写回报文）。
 *
 * @param packet    指向完整以太网帧（包含以太网头，可带 VLAN tag）。
 * @param len       从以太网头到载荷结尾（不含 iCRC 字段）的字节长度。
 * @param out_icrc  输出 32 位 iCRC（主机字节序）。
 * @return 0 成功，非 0 失败。
 */
int rocev2_icrc(const uint8_t *packet, size_t len, uint32_t *out_icrc);

/* --- High-level frame APIs --- */

/**
 * 计算并填写 RoCEv2 iCRC。
 *
 * @param packet  指向完整以太网帧（包含末尾 4 字节 iCRC 字段）。
 * @param len     完整帧长度（包含末尾 iCRC 字段）。
 * @return 0 成功，非 0 失败。
 *
 * 说明：iCRC 会按网络字节序（大端）写入到最后 4 字节。
 */
int rocev2_icrc_fill(uint8_t *packet, size_t len);

/**
 * 校验 RoCEv2 iCRC。
 *
 * @param packet  指向完整以太网帧（包含末尾 4 字节 iCRC 字段）。
 * @param len     完整帧长度（包含末尾 iCRC 字段）。
 * @return 0 校验通过，1 校验不通过，负数为参数或解析失败。
 *
 * 兼容性说明：校验时同时兼容 iCRC 尾字段的大端/小端编码；
 * 推荐发送端使用大端。
 */
int rocev2_icrc_verify(const uint8_t *packet, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ROCEV2_CRC_H */
