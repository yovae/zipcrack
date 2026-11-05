/* Hot loop for zipcrack.py: legacy ZipCrypto password checks. */
#include <stdint.h>
#include <string.h>

#define API __declspec(dllexport)

#define ZIP_INIT0 305419896u
#define ZIP_INIT1 591751049u
#define ZIP_INIT2 878082192u

static uint32_t crc_table[256];
static int crc_ready = 0;

static void init_crc(void) {
    uint32_t i, c;
    int j;
    if (crc_ready) {
        return;
    }
    for (i = 0; i < 256u; i++) {
        c = i;
        for (j = 0; j < 8; j++) {
            if (c & 1u) {
                c = 0xEDB88320u ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        crc_table[i] = c;
    }
    crc_ready = 1;
}

static inline void update_keys(uint32_t *k0, uint32_t *k1, uint32_t *k2, uint8_t b) {
    uint32_t n0 = crc_table[(*k0 ^ b) & 0xFFu] ^ (*k0 >> 8);
    uint32_t n1 = *k1 + (n0 & 0xFFu);
    n1 = n1 * 134775813u + 1u;
    uint32_t n2 = crc_table[(*k2 ^ (n1 >> 24)) & 0xFFu] ^ (*k2 >> 8);
    *k0 = n0;
    *k1 = n1;
    *k2 = n2;
}

static inline uint8_t keystream(uint32_t k2) {
    uint32_t t = (k2 | 2u) & 0xFFFFu;
    return (uint8_t)((t * (t ^ 1u)) >> 8);
}

static int password_matches(
    uint32_t k0,
    uint32_t k1,
    uint32_t k2,
    const uint8_t *suffix,
    int suffix_len,
    const uint8_t *cipher,
    int cipher_len,
    uint32_t expected_crc,
    uint8_t check_byte
) {
    int i;
    uint8_t last = 0;
    uint32_t crc;

    for (i = 0; i < suffix_len; i++) {
        update_keys(&k0, &k1, &k2, suffix[i]);
    }
    for (i = 0; i < 12; i++) {
        uint8_t plain = (uint8_t)(cipher[i] ^ keystream(k2));
        update_keys(&k0, &k1, &k2, plain);
        last = plain;
    }
    if (last != check_byte) {
        return 0;
    }
    crc = 0xFFFFFFFFu;
    for (i = 12; i < cipher_len; i++) {
        uint8_t plain = (uint8_t)(cipher[i] ^ keystream(k2));
        update_keys(&k0, &k1, &k2, plain);
        crc = crc_table[(crc ^ plain) & 0xFFu] ^ (crc >> 8);
    }
    crc ^= 0xFFFFFFFFu;
    return crc == expected_crc;
}

API int zipcrack_version(void) {
    return 1;
}

API int check_password(
    const uint8_t *pw,
    int pwlen,
    const uint8_t *cipher,
    int cipher_len,
    uint32_t expected_crc,
    uint8_t check_byte
) {
    uint32_t k0, k1, k2;
    int i;

    init_crc();
    if (pwlen < 0 || cipher == NULL || cipher_len < 12) {
        return 0;
    }
    k0 = ZIP_INIT0;
    k1 = ZIP_INIT1;
    k2 = ZIP_INIT2;
    for (i = 0; i < pwlen; i++) {
        update_keys(&k0, &k1, &k2, pw[i]);
    }
    return password_matches(k0, k1, k2, NULL, 0, cipher, cipher_len, expected_crc, check_byte);
}

API int check_batch(
    const uint8_t *packed,
    int packed_len,
    int count,
    const uint8_t *cipher,
    int cipher_len,
    uint32_t expected_crc,
    uint8_t check_byte,
    uint8_t *out_pw,
    int *out_len
) {
    int offset = 0;
    int i;

    init_crc();
    if (packed == NULL || count < 0 || packed_len < 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        int len;
        if (offset + 2 > packed_len) {
            return 0;
        }
        len = (int)packed[offset] | ((int)packed[offset + 1] << 8);
        offset += 2;
        if (len < 0 || len > 256 || offset + len > packed_len) {
            return 0;
        }
        if (check_password(packed + offset, len, cipher, cipher_len, expected_crc, check_byte)) {
            memcpy(out_pw, packed + offset, (size_t)len);
            *out_len = len;
            return 1;
        }
        offset += len;
    }
    return 0;
}

API int crack_range(
    const uint8_t *charset,
    int charset_len,
    int length,
    uint64_t start,
    uint64_t count,
    uint32_t init0,
    uint32_t init1,
    uint32_t init2,
    const uint8_t *suffix,
    int suffix_len,
    const uint8_t *cipher,
    int cipher_len,
    uint32_t expected_crc,
    uint8_t check_byte,
    uint64_t *tested,
    uint8_t *out_pw
) {
    uint8_t pw[64];
    int dig[64];
    uint32_t pk0[65], pk1[65], pk2[65];
    uint64_t idx;
    uint64_t done = 0;
    int i;

    init_crc();
    if (tested) {
        *tested = 0;
    }
    if (charset == NULL || cipher == NULL || out_pw == NULL) {
        return 0;
    }
    if (length <= 0 || length > 64 || charset_len <= 0 || charset_len > 256) {
        return 0;
    }
    if (suffix_len < 0 || suffix_len > 128 || cipher_len < 12 || count == 0) {
        return 0;
    }
    if (suffix_len > 0 && suffix == NULL) {
        return 0;
    }

    idx = start;
    for (i = length - 1; i >= 0; --i) {
        dig[i] = (int)(idx % (uint64_t)charset_len);
        pw[i] = charset[dig[i]];
        idx /= (uint64_t)charset_len;
    }

    pk0[0] = init0;
    pk1[0] = init1;
    pk2[0] = init2;
    for (i = 0; i < length; i++) {
        pk0[i + 1] = pk0[i];
        pk1[i + 1] = pk1[i];
        pk2[i + 1] = pk2[i];
        update_keys(&pk0[i + 1], &pk1[i + 1], &pk2[i + 1], pw[i]);
    }

    while (done < count) {
        if (password_matches(
                pk0[length], pk1[length], pk2[length],
                suffix, suffix_len,
                cipher, cipher_len,
                expected_crc, check_byte)) {
            memcpy(out_pw, pw, (size_t)length);
            done++;
            if (tested) {
                *tested = done;
            }
            return 1;
        }
        done++;
        if (done == count) {
            break;
        }

        {
            int pos = length - 1;
            for (;;) {
                dig[pos] += 1;
                if (dig[pos] < charset_len) {
                    pw[pos] = charset[dig[pos]];
                    break;
                }
                dig[pos] = 0;
                pw[pos] = charset[0];
                if (pos == 0) {
                    pos = -1;
                    break;
                }
                pos--;
            }
            if (pos < 0) {
                break;
            }
            for (i = pos; i < length; i++) {
                pk0[i + 1] = pk0[i];
                pk1[i + 1] = pk1[i];
                pk2[i + 1] = pk2[i];
                update_keys(&pk0[i + 1], &pk1[i + 1], &pk2[i + 1], pw[i]);
            }
        }
    }

    if (tested) {
        *tested = done;
    }
    return 0;
}
