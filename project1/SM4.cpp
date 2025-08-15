#include <iostream>
#include <iomanip>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

// SM4基本参数定义
constexpr uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
constexpr uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// S盒
constexpr uint8_t SBOX[256] = {
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

// 循环左移
inline uint32_t rotate_left(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// 合成置换函数T
inline uint32_t tau(uint32_t x) {
    uint32_t b0 = SBOX[x >> 24];
    uint32_t b1 = SBOX[(x >> 16) & 0xff];
    uint32_t b2 = SBOX[(x >> 8) & 0xff];
    uint32_t b3 = SBOX[x & 0xff];
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

inline uint32_t L(uint32_t x) {
    return x ^ rotate_left(x, 2) ^ rotate_left(x, 10) ^ rotate_left(x, 18) ^ rotate_left(x, 24);
}

inline uint32_t L_prime(uint32_t x) {
    return x ^ rotate_left(x, 13) ^ rotate_left(x, 23);
}

inline uint32_t T(uint32_t x) {
    return L(tau(x));
}

inline uint32_t T_prime(uint32_t x) {
    return L_prime(tau(x));
}

// 轮函数F
inline uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    return x0 ^ T(x1 ^ x2 ^ x3 ^ rk);
}

// 密钥扩展算法
void expand_key(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];

    // 初始化中间密钥
    K[0] = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3];
    K[1] = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7];
    K[2] = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11];
    K[3] = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15];

    // 初始变换
    K[0] ^= FK[0];
    K[1] ^= FK[1];
    K[2] ^= FK[2];
    K[3] ^= FK[3];

    // 生成轮密钥
    for (int i = 0; i < 32; ++i) {
        K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// SM4加密函数
void sm4_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];

    // 初始化输入
    X[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    X[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    X[2] = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    X[3] = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

    // 32轮迭代
    for (int i = 0; i < 32; ++i) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[i]);
    }

    // 反序变换
    out[0] = X[35] >> 24; out[1] = X[35] >> 16; out[2] = X[35] >> 8; out[3] = X[35];
    out[4] = X[34] >> 24; out[5] = X[34] >> 16; out[6] = X[34] >> 8; out[7] = X[34];
    out[8] = X[33] >> 24; out[9] = X[33] >> 16; out[10] = X[33] >> 8; out[11] = X[33];
    out[12] = X[32] >> 24; out[13] = X[32] >> 16; out[14] = X[32] >> 8; out[15] = X[32];
}

// SM4解密函数
void sm4_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];

    // 初始化输入
    X[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    X[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    X[2] = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    X[3] = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

    // 32轮迭代(使用逆序轮密钥)
    for (int i = 0; i < 32; ++i) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[31 - i]);
    }

    // 反序变换
    out[0] = X[35] >> 24; out[1] = X[35] >> 16; out[2] = X[35] >> 8; out[3] = X[35];
    out[4] = X[34] >> 24; out[5] = X[34] >> 16; out[6] = X[34] >> 8; out[7] = X[34];
    out[8] = X[33] >> 24; out[9] = X[33] >> 16; out[10] = X[33] >> 8; out[11] = X[33];
    out[12] = X[32] >> 24; out[13] = X[32] >> 16; out[14] = X[32] >> 8; out[15] = X[32];
}

// 打印16进制数据
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

// 性能测试函数
void measure_performance(const std::string& name, void (*func)(const uint8_t[16], uint8_t[16], const uint32_t[32]),
    const uint8_t* input, uint8_t* output, const uint32_t* rk,
    int iterations = 100000) {
    clock_t start = clock();
    for (int i = 0; i < iterations; ++i) {
        func(input, output, rk);
    }
    clock_t end = clock();

    double elapsed = double(end - start) / CLOCKS_PER_SEC;
    double speed = (iterations * 16) / (elapsed * 1024 * 1024); // MB/s

    std::cout << name << " performance (" << iterations << " iterations):" << std::endl;
    std::cout << "  Total time: " << elapsed << " seconds" << std::endl;
    std::cout << "  Speed: " << speed << " MB/s" << std::endl;
    std::cout << "  Time per block: " << (elapsed * 1000000 / iterations) << " μs" << std::endl;
}

int main() {
    // 密钥和明文
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t plaintext[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    // 扩展密钥
    uint32_t rk[32];
    expand_key(key, rk);

    // 加密
    sm4_encrypt(plaintext, ciphertext, rk);

    // 解密
    sm4_decrypt(ciphertext, decrypted, rk);

    // 输出结果
    std::cout << "Plaintext:  ";
    print_hex(plaintext, 16);

    std::cout << "Ciphertext: ";
    print_hex(ciphertext, 16);

    std::cout << "Decrypted:  ";
    print_hex(decrypted, 16);

    // 验证加解密是否正确
    bool success = true;
    for (int i = 0; i < 16; ++i) {
        if (plaintext[i] != decrypted[i]) {
            success = false;
            break;
        }
    }
    std::cout << "Decryption " << (success ? "successful" : "failed") << std::endl;

    // 性能测试
    const int iterations = 1000000; // 增加迭代次数以获得更准确的结果

    std::cout << "\nPerformance Testing (iterations: " << iterations << ")\n";
    std::cout << "=====================================\n";

    // 测试加密性能
    measure_performance("Encryption", sm4_encrypt, plaintext, ciphertext, rk, iterations);

    // 测试解密性能
    measure_performance("Decryption", sm4_decrypt, ciphertext, decrypted, rk, iterations);

    return 0;
}