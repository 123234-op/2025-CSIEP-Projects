#include <iostream>
#include <iomanip>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>

// SM4 参数
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t ROUNDS = 32;

alignas(16) const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// SM4 FK constants (系统参数)
const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// SM4 CK constants (固定参数)
const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 旋转操作函数
inline uint32_t rotate_left(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// SM4 轮函数
inline uint32_t sm4_round_function(uint32_t x) {
    uint8_t b[4];
    b[0] = SBOX[(x >> 24) & 0xFF];
    b[1] = SBOX[(x >> 16) & 0xFF];
    b[2] = SBOX[(x >> 8) & 0xFF];
    b[3] = SBOX[x & 0xFF];

    uint32_t result = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    result ^= rotate_left(result, 2);
    result ^= rotate_left(result, 10);
    result ^= rotate_left(result, 18);
    result ^= rotate_left(result, 24);

    return result;
}

// SM4 密钥扩展
void sm4_key_expansion(const uint8_t key[16], uint32_t rk[ROUNDS]) {
    uint32_t mk[4];
    for (int i = 0; i < 4; ++i) {
        mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    uint32_t k[36];
    for (int i = 0; i < 4; ++i) {
        k[i] = mk[i] ^ FK[i];
    }

    for (int i = 0; i < 32; ++i) {
        uint32_t tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        k[i + 4] = k[i] ^ sm4_round_function(tmp);
        rk[i] = k[i + 4];
    }
}

// SM4 加密/解密
void sm4_crypt(const uint32_t rk[ROUNDS], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[36];
    x[0] = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
    x[1] = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
    x[2] = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
    x[3] = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];

    for (int i = 0; i < 32; ++i) {
        uint32_t tmp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];
        x[i + 4] = x[i] ^ sm4_round_function(tmp);
    }

    out[0] = (x[35] >> 24) & 0xFF;
    out[1] = (x[35] >> 16) & 0xFF;
    out[2] = (x[35] >> 8) & 0xFF;
    out[3] = x[35] & 0xFF;
    out[4] = (x[34] >> 24) & 0xFF;
    out[5] = (x[34] >> 16) & 0xFF;
    out[6] = (x[34] >> 8) & 0xFF;
    out[7] = x[34] & 0xFF;
    out[8] = (x[33] >> 24) & 0xFF;
    out[9] = (x[33] >> 16) & 0xFF;
    out[10] = (x[33] >> 8) & 0xFF;
    out[11] = x[33] & 0xFF;
    out[12] = (x[32] >> 24) & 0xFF;
    out[13] = (x[32] >> 16) & 0xFF;
    out[14] = (x[32] >> 8) & 0xFF;
    out[15] = x[32] & 0xFF;
}

// GCM 定义
const size_t GHASH_TABLE_SIZE = 16 * 16;
alignas(16) uint8_t GHASH_TABLE[GHASH_TABLE_SIZE];

// 初始化 GHASH 预计算表
void init_ghash_table(const uint8_t H[16]) {
    uint8_t tmp[16] = { 0 };
    uint8_t product[16] = { 0 };

    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            tmp[i] = j;
            memset(product, 0, 16);

            for (int k = 0; k < 8; ++k) {
                if (tmp[i] & (1 << (7 - k))) {
                    for (int m = 0; m < 16; ++m) {
                        product[m] ^= H[m];
                    }
                }

                int carry = product[0] & 0x01;
                for (int m = 0; m < 15; ++m) {
                    product[m] = (product[m] >> 1) | ((product[m + 1] & 0x01) << 7);
                }
                product[15] >>= 1;
                if (carry) {
                    product[15] ^= 0xE1;
                }
            }

            memcpy(&GHASH_TABLE[i * 16 + j * 16], product, 16);
        }
    }
}

// 使用预计算表优化 GHASH
void ghash_optimized(const uint8_t* data, size_t len, uint8_t result[16]) {
    __m128i x = _mm_setzero_si128();
    const uint8_t* ptr = data;

    for (size_t i = 0; i < len; i += 16) {
        size_t block_len = (len - i) > 16 ? 16 : (len - i);
        uint8_t block[16] = { 0 };
        memcpy(block, ptr + i, block_len);

        __m128i y = _mm_loadu_si128((const __m128i*)block);
        x = _mm_xor_si128(x, y);

        for (int j = 0; j < 16; ++j) {
            uint8_t b = ((uint8_t*)&x)[15 - j];
            __m128i h = _mm_load_si128((const __m128i*)(GHASH_TABLE + j * 16 * 16 + b * 16));
            x = _mm_xor_si128(x, h);
        }
    }

    _mm_storeu_si128((__m128i*)result, x);
}

// SM4-GCM 加密
void sm4_gcm_encrypt(const uint32_t rk[ROUNDS],
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t tag[16]) {
    // 1. 生成哈希子密钥H
    uint8_t H[16] = { 0 };
    sm4_crypt(rk, H, H);

    // 2. 初始化GHASH表
    init_ghash_table(H);

    // 3. 生成J0 (初始计数器)
    uint8_t J0[16] = { 0 };
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 0x01;
    }
    else {
        ghash_optimized(iv, iv_len, J0);
        uint8_t len_bytes[16] = { 0 };
        *reinterpret_cast<uint64_t*>(&len_bytes[8]) = static_cast<uint64_t>(iv_len) * 8;
        ghash_optimized(len_bytes, 16, J0);
    }

    // 4. 加密计数器块
    uint8_t ctr_block[16];
    memcpy(ctr_block, J0, 16);
    ctr_block[15] += 1;

    uint8_t eky0[16];
    sm4_crypt(rk, ctr_block, eky0);

    // 5. 加密明文
    for (size_t i = 0; i < plaintext_len; i += 16) {
        ctr_block[15] += 1;
        uint8_t ek[16];
        sm4_crypt(rk, ctr_block, ek);

        size_t block_len = (plaintext_len - i) > 16 ? 16 : (plaintext_len - i);
        for (size_t j = 0; j < block_len; ++j) {
            ciphertext[i + j] = plaintext[i + j] ^ ek[j];
        }
    }

    // 6. 计算认证标签
    size_t auth_data_len = aad_len + plaintext_len + 16;
    uint8_t* auth_data = new uint8_t[auth_data_len];
    size_t offset = 0;

    // 添加AAD
    if (aad_len > 0) {
        memcpy(auth_data + offset, aad, aad_len);
        offset += aad_len;
    }

    // 添加密文
    memcpy(auth_data + offset, ciphertext, plaintext_len);
    offset += plaintext_len;

    // 添加长度信息
    uint8_t len_block[16] = { 0 };
    *reinterpret_cast<uint64_t*>(&len_block[0]) = static_cast<uint64_t>(aad_len) * 8;
    *reinterpret_cast<uint64_t*>(&len_block[8]) = static_cast<uint64_t>(plaintext_len) * 8;
    memcpy(auth_data + offset, len_block, 16);

    // 计算GHASH
    uint8_t ghash_result[16];
    ghash_optimized(auth_data, auth_data_len, ghash_result);

    // 生成标签
    for (int i = 0; i < 16; ++i) {
        tag[i] = ghash_result[i] ^ eky0[i];
    }

    delete[] auth_data;
}

// SM4-GCM 解密
bool sm4_gcm_decrypt(const uint32_t rk[ROUNDS],
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t* plaintext) {
    // 1. 生成哈希子密钥H
    uint8_t H[16] = { 0 };
    sm4_crypt(rk, H, H);

    // 2. 初始化GHASH表
    init_ghash_table(H);

    // 3. 生成J0 (初始计数器)
    uint8_t J0[16] = { 0 };
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 0x01;
    }
    else {
        ghash_optimized(iv, iv_len, J0);
        uint8_t len_bytes[16] = { 0 };
        *reinterpret_cast<uint64_t*>(&len_bytes[8]) = static_cast<uint64_t>(iv_len) * 8;
        ghash_optimized(len_bytes, 16, J0);
    }

    // 4. 加密计数器块
    uint8_t ctr_block[16];
    memcpy(ctr_block, J0, 16);
    ctr_block[15] += 1;

    uint8_t eky0[16];
    sm4_crypt(rk, ctr_block, eky0);

    // 5. 计算认证标签
    size_t auth_data_len = aad_len + ciphertext_len + 16;
    uint8_t* auth_data = new uint8_t[auth_data_len];
    size_t offset = 0;

    // 添加AAD
    if (aad_len > 0) {
        memcpy(auth_data + offset, aad, aad_len);
        offset += aad_len;
    }

    // 添加密文
    memcpy(auth_data + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;

    // 添加长度信息
    uint8_t len_block[16] = { 0 };
    *reinterpret_cast<uint64_t*>(&len_block[0]) = static_cast<uint64_t>(aad_len) * 8;
    *reinterpret_cast<uint64_t*>(&len_block[8]) = static_cast<uint64_t>(ciphertext_len) * 8;
    memcpy(auth_data + offset, len_block, 16);

    // 计算GHASH
    uint8_t ghash_result[16];
    ghash_optimized(auth_data, auth_data_len, ghash_result);

    // 验证标签
    uint8_t computed_tag[16];
    for (int i = 0; i < 16; ++i) {
        computed_tag[i] = ghash_result[i] ^ eky0[i];
    }

    bool auth_success = true;
    for (int i = 0; i < 16; ++i) {
        if (computed_tag[i] != tag[i]) {
            auth_success = false;
            break;
        }
    }

    delete[] auth_data;

    if (!auth_success) {
        return false; // 认证失败
    }

    // 6. 解密密文
    for (size_t i = 0; i < ciphertext_len; i += 16) {
        ctr_block[15] += 1;
        uint8_t ek[16];
        sm4_crypt(rk, ctr_block, ek);

        size_t block_len = (ciphertext_len - i) > 16 ? 16 : (ciphertext_len - i);
        for (size_t j = 0; j < block_len; ++j) {
            plaintext[i + j] = ciphertext[i + j] ^ ek[j];
        }
    }

    return true;
}

// 测试函数
void test_sm4_gcm() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    const char* plaintext_str = "This is a test message for SM4-GCM mode.";
    size_t plaintext_len = strlen(plaintext_str);
    uint8_t* plaintext = new uint8_t[plaintext_len];
    memcpy(plaintext, plaintext_str, plaintext_len);

    const char* aad_str = "Additional authenticated data";
    size_t aad_len = strlen(aad_str);
    uint8_t* aad = new uint8_t[aad_len];
    memcpy(aad, aad_str, aad_len);

    uint8_t* ciphertext = new uint8_t[plaintext_len];
    uint8_t* decrypted = new uint8_t[plaintext_len];
    uint8_t tag[16] = { 0 };

    uint32_t rk[ROUNDS];
    sm4_key_expansion(key, rk);

    // 加密
    sm4_gcm_encrypt(rk, plaintext, plaintext_len, iv, sizeof(iv),
        aad, aad_len, ciphertext, tag);

    std::cout << "Ciphertext: ";
    for (size_t i = 0; i < plaintext_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << (int)ciphertext[i] << " ";
    }
    std::cout << "\nTag: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << (int)tag[i] << " ";
    }
    std::cout << std::endl;

    // 解密
    bool success = sm4_gcm_decrypt(rk, ciphertext, plaintext_len, iv, sizeof(iv),
        aad, aad_len, tag, decrypted);

    if (success) {
        std::cout << "Decryption successful!\nPlaintext: "
            << decrypted << std::endl;
    }
    else {
        std::cout << "Authentication failed!" << std::endl;
    }

    delete[] plaintext;
    delete[] aad;
    delete[] ciphertext;
    delete[] decrypted;
}

int main() {
    test_sm4_gcm();
    return 0;
}