#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <array>

// SM4 算法参数
constexpr size_t BLOCK_SIZE = 16; // 128位分组
constexpr size_t ROUNDS = 32;     // 32轮运算

// SM4 S盒
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

// SM4 FK常量
constexpr uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// SM4 CK常量
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

// SM4的T表（结合S盒和线性变换L）
uint32_t T_table[256];

// 初始化T表
void init_T_table() {
    for (int i = 0; i < 256; ++i) {
        uint8_t a = SBOX[i];
        // L'变换：L'(a) = a ^ (a << 2) ^ (a << 10) ^ (a << 18) ^ (a << 24)
        uint32_t l_prime = (a) ^ ((a << 2) | (a >> 6)) ^ ((a << 10) | (a >> 22)) ^
            ((a << 18) | (a >> 14)) ^ ((a << 24) | (a >> 8));
        T_table[i] = l_prime;
    }
}

// 循环左移
inline uint32_t rotate_left(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// 使用T表的SM4轮函数
inline uint32_t sm4_round_function(uint32_t x) {
    uint32_t b0 = (x >> 24) & 0xFF;
    uint32_t b1 = (x >> 16) & 0xFF;
    uint32_t b2 = (x >> 8) & 0xFF;
    uint32_t b3 = x & 0xFF;

    return T_table[b0] ^ rotate_left(T_table[b1], 8) ^
        rotate_left(T_table[b2], 16) ^ rotate_left(T_table[b3], 24);
}

// 密钥扩展
void sm4_key_expansion(const uint8_t key[16], uint32_t rk[ROUNDS]) {
    uint32_t mk[4];

    // 将密钥字节转换为字
    for (int i = 0; i < 4; ++i) {
        mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    // 中间密钥（K）
    uint32_t k[36];
    for (int i = 0; i < 4; ++i) {
        k[i] = mk[i] ^ FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < 32; ++i) {
        uint32_t tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        k[i + 4] = k[i] ^ sm4_round_function(tmp);
        rk[i] = k[i + 4];
    }
}

// SM4加密/解密（结构相同，只是轮密钥顺序不同）
void sm4_crypt(const uint32_t rk[ROUNDS], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[36];

    // 将输入字节转换为字
    for (int i = 0; i < 4; ++i) {
        x[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) | (in[4 * i + 2] << 8) | in[4 * i + 3];
    }

    // 32轮运算
    for (int i = 0; i < 32; ++i) {
        uint32_t tmp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];
        x[i + 4] = x[i] ^ sm4_round_function(tmp);
    }

    // 将字转换为输出字节（最后4个字逆序）
    for (int i = 0; i < 4; ++i) {
        out[4 * i] = (x[35 - i] >> 24) & 0xFF;
        out[4 * i + 1] = (x[35 - i] >> 16) & 0xFF;
        out[4 * i + 2] = (x[35 - i] >> 8) & 0xFF;
        out[4 * i + 3] = x[35 - i] & 0xFF;
    }
}

// 打印十六进制数据
void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

// 性能测试
void performance_test(int iterations = 100000) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    uint32_t rk[ROUNDS];

    // 初始化T表
    init_T_table();

    // 密钥扩展
    sm4_key_expansion(key, rk);

    // 预热
    for (int i = 0; i < 1000; ++i) {
        sm4_crypt(rk, plaintext, ciphertext);
    }

    // 加密性能测试
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sm4_crypt(rk, plaintext, ciphertext);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto encrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    double encrypt_speed = (double)iterations * BLOCK_SIZE / (encrypt_time / 1000000.0) / (1024 * 1024); // MB/s

    // 准备解密轮密钥（逆序）
    uint32_t drk[ROUNDS];
    for (int i = 0; i < ROUNDS; ++i) {
        drk[i] = rk[ROUNDS - 1 - i];
    }

    // 解密性能测试
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sm4_crypt(drk, ciphertext, decrypted);
    }
    end = std::chrono::high_resolution_clock::now();
    auto decrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    double decrypt_speed = (double)iterations * BLOCK_SIZE / (decrypt_time / 1000000.0) / (1024 * 1024); // MB/s

    // 打印结果
    std::cout << "Performance Results (T-table implementation):\n";
    std::cout << "Encryption time for " << iterations << " blocks: " << encrypt_time << " us\n";
    std::cout << "Encryption speed: " << encrypt_speed << " MB/s\n";
    std::cout << "Decryption time for " << iterations << " blocks: " << decrypt_time << " us\n";
    std::cout << "Decryption speed: " << decrypt_speed << " MB/s\n";


    // 验证正确性
    if (memcmp(plaintext, decrypted, BLOCK_SIZE)) {
        std::cerr << "Error: Decryption result doesn't match plaintext!\n";
        print_hex("Plaintext ", plaintext, BLOCK_SIZE);
        print_hex("Decrypted", decrypted, BLOCK_SIZE);
    }
}

int main() {
    // 初始化T表
    init_T_table();

    // SM4标准测试向量
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    uint32_t rk[ROUNDS];

    // 密钥扩展
    sm4_key_expansion(key, rk);

    // 加密
    sm4_crypt(rk, plaintext, ciphertext);
    print_hex("Ciphertext", ciphertext, BLOCK_SIZE);


    // 准备解密轮密钥（逆序）
    uint32_t drk[ROUNDS];
    for (int i = 0; i < ROUNDS; ++i) {
        drk[i] = rk[ROUNDS - 1 - i];
    }

    // 解密
    sm4_crypt(drk, ciphertext, decrypted);
    print_hex("Decrypted ", decrypted, BLOCK_SIZE);

    // 验证
    if (memcmp(plaintext, decrypted, BLOCK_SIZE) == 0) {
        std::cout << "SM4 encryption/decryption successful!\n";
    }
    else {
        std::cout << "SM4 encryption/decryption failed!\n";
    }

    // 性能测试
    performance_test();

    return 0;
}
