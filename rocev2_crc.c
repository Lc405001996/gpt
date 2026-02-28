#include "rocev2_crc.h"

#include <stdlib.h>
#include <string.h>

#define CRC32_POLY_REFLECTED 0xEDB88320u

#define ETH_HDR_LEN 14u
#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_IPV6 0x86DDu
#define ETHERTYPE_VLAN_8021Q 0x8100u
#define ETHERTYPE_VLAN_8021AD 0x88A8u
#define VLAN_TAG_LEN 4u
#define ICRC_LEN 4u
#define IPPROTO_UDP 17u

static uint32_t crc32_table[256];
static int crc32_table_ready = 0;
static const uint8_t rocev2_preface[8] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
};

struct mutable_byte {
    size_t off;
    uint8_t value;
};

struct crc_mask_plan {
    size_t ip_off;
    struct mutable_byte bytes[8];
    size_t count;
};

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[3]) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[0] << 24);
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xFFu);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >> 8) & 0xFFu);
    p[3] = (uint8_t)(v & 0xFFu);
}

static void crc32_init_table(void) {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int b = 0; b < 8; ++b) {
            c = (c & 1u) ? ((c >> 1) ^ CRC32_POLY_REFLECTED) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    if (!crc32_table_ready) {
        crc32_init_table();
    }

    for (size_t i = 0; i < len; ++i) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFFu];
    }
    return crc;
}

static int parse_eth_ip_offset(const uint8_t *pkt, size_t len, size_t *ip_off) {
    if (len < ETH_HDR_LEN) {
        return -1;
    }

    size_t off = ETH_HDR_LEN;
    uint16_t ether_type = read_be16(pkt + 12);

    while (ether_type == ETHERTYPE_VLAN_8021Q || ether_type == ETHERTYPE_VLAN_8021AD) {
        if (off + VLAN_TAG_LEN > len) {
            return -1;
        }
        ether_type = read_be16(pkt + off + 2);
        off += VLAN_TAG_LEN;
    }

    if (ether_type != ETHERTYPE_IPV4 && ether_type != ETHERTYPE_IPV6) {
        return -1;
    }
    if (off >= len) {
        return -1;
    }

    *ip_off = off;
    return 0;
}

static int rocev2_plan_mutable_fields(const uint8_t *pkt, size_t len, size_t ip_off, struct crc_mask_plan *plan) {
    if (ip_off >= len || !plan) {
        return -1;
    }

    size_t udp_off;
    size_t bth_off;
    const uint8_t *ip = pkt + ip_off;
    size_t ip_len = len - ip_off;

    plan->ip_off = ip_off;
    plan->count = 0;

    uint8_t version = ip[0] >> 4;
    if (version == 4u) {
        if (ip_len < 20) {
            return -1;
        }

        size_t ihl = (size_t)(ip[0] & 0x0Fu) * 4u;
        if (ihl < 20 || ihl > ip_len) {
            return -1;
        }

        if (ip[9] != IPPROTO_UDP) {
            return -1;
        }

        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 1, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 8, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 10, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 11, .value = 0xFFu };

        udp_off = ip_off + ihl;
    } else if (version == 6u) {
        if (ip_len < 40) {
            return -1;
        }

        if (ip[6] != IPPROTO_UDP) {
            return -1;
        }

        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 0, .value = (uint8_t)((ip[0] & 0xF0u) | 0x0Fu) };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 1, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 2, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 3, .value = 0xFFu };
        plan->bytes[plan->count++] = (struct mutable_byte){ .off = ip_off + 7, .value = 0xFFu };

        udp_off = ip_off + 40;
    } else {
        return -1;
    }

    if (udp_off + 8 > len) {
        return -1;
    }

    plan->bytes[plan->count++] = (struct mutable_byte){ .off = udp_off + 6, .value = 0xFFu };
    plan->bytes[plan->count++] = (struct mutable_byte){ .off = udp_off + 7, .value = 0xFFu };

    bth_off = udp_off + 8;
    if (bth_off + 12 > len) {
        return -1;
    }

    plan->bytes[plan->count++] = (struct mutable_byte){ .off = bth_off + 4, .value = 0xFFu };
    return 0;
}

static uint32_t crc32_update_masked(uint32_t crc, const uint8_t *packet, size_t len, const struct crc_mask_plan *plan) {
    size_t cursor = plan->ip_off;

    for (size_t i = 0; i < plan->count; ++i) {
        size_t m_off = plan->bytes[i].off;
        if (m_off > cursor) {
            crc = crc32_update(crc, packet + cursor, m_off - cursor);
        }

        crc = (crc >> 8) ^ crc32_table[(crc ^ plan->bytes[i].value) & 0xFFu];
        cursor = m_off + 1;
    }

    if (cursor < len) {
        crc = crc32_update(crc, packet + cursor, len - cursor);
    }
    return crc;
}

int rocev2_icrc(const uint8_t *packet, size_t len, uint32_t *out_icrc) {
    if (!packet || !out_icrc || len == 0) {
        return -1;
    }

    size_t ip_off = 0;
    if (parse_eth_ip_offset(packet, len, &ip_off) != 0) {
        return -1;
    }

    struct crc_mask_plan plan;
    if (rocev2_plan_mutable_fields(packet, len, ip_off, &plan) != 0) {
        return -1;
    }

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, rocev2_preface, sizeof(rocev2_preface));
    crc = crc32_update_masked(crc, packet, len, &plan);
    crc ^= 0xFFFFFFFFu;

    *out_icrc = crc;
    return 0;
}

/*
 * High-level API #1: compute and fill iCRC to the last 4 bytes of frame
 */
int rocev2_icrc_fill(uint8_t *packet, size_t len) {
    if (!packet || len <= ICRC_LEN) {
        return -1;
    }

    uint32_t icrc = 0;
    if (rocev2_icrc(packet, len - ICRC_LEN, &icrc) != 0) {
        return -1;
    }

    write_be32(packet + (len - ICRC_LEN), icrc);
    return 0;
}

/*
 * High-level API #2: verify iCRC from the last 4 bytes of frame
 */
int rocev2_icrc_verify(const uint8_t *packet, size_t len) {
    if (!packet || len <= ICRC_LEN) {
        return -1;
    }

    uint32_t computed = 0;
    if (rocev2_icrc(packet, len - ICRC_LEN, &computed) != 0) {
        return -1;
    }

    uint32_t actual_be = read_be32(packet + (len - ICRC_LEN));
    uint32_t actual_le = read_le32(packet + (len - ICRC_LEN));
    if (computed == actual_be || computed == actual_le) {
        return 0;
    }

    return 1;
}

#ifdef ROCEV2_CRC_DEMO
#include <stdio.h>

int main(void) {
    uint8_t sample_eth_ipv4_udp_bth_icrc[14 + 20 + 8 + 12 + 4] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x2C, 0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02, 0x12, 0xB7, 0x12, 0xB7,
        0x00, 0x18, 0x00, 0x00, 0x81, 0x00, 0xFF, 0xFF,
        0x00, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    if (rocev2_icrc_fill(sample_eth_ipv4_udp_bth_icrc, sizeof(sample_eth_ipv4_udp_bth_icrc)) != 0) {
        fprintf(stderr, "icrc fill failed\n");
        return 1;
    }

    printf("iCRC bytes = %02X %02X %02X %02X\n",
           sample_eth_ipv4_udp_bth_icrc[sizeof(sample_eth_ipv4_udp_bth_icrc) - 4],
           sample_eth_ipv4_udp_bth_icrc[sizeof(sample_eth_ipv4_udp_bth_icrc) - 3],
           sample_eth_ipv4_udp_bth_icrc[sizeof(sample_eth_ipv4_udp_bth_icrc) - 2],
           sample_eth_ipv4_udp_bth_icrc[sizeof(sample_eth_ipv4_udp_bth_icrc) - 1]);

    if (rocev2_icrc_verify(sample_eth_ipv4_udp_bth_icrc, sizeof(sample_eth_ipv4_udp_bth_icrc)) == 0) {
        puts("verify PASS");
        return 0;
    }

    puts("verify FAIL");
    return 2;
}
#endif
