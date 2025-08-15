#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <iomanip>

// SM3����ʵ��
class SM3 {
public:
    SM3() {
        reset();
    }

    void reset() {
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;
        count = 0;
    }

    void update(const unsigned char* data, size_t len) {
        size_t index = count % 64;
        count += len;

        // ���������е�����
        if (index + len < 64) {
            memcpy(buffer + index, data, len);
            return;
        }

        // ��仺����������
        memcpy(buffer + index, data, 64 - index);
        processBlock(buffer);

        // ���������Ŀ�
        size_t i = 64 - index;
        for (; i + 64 <= len; i += 64) {
            processBlock(data + i);
        }

        // ����ʣ������
        memcpy(buffer, data + i, len - i);
    }

    void final(unsigned char digest[32]) {
        size_t index = count % 64;
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);

        // ������
        unsigned char padding[64] = { 0 };
        padding[0] = 0x80;
        update(padding, padLen);

        // ��ӳ���
        uint64_t bitCount = count * 8;
        for (int i = 0; i < 8; ++i) {
            padding[i] = (bitCount >> ((7 - i) * 8)) & 0xFF;
        }
        update(padding, 8);

        // �����ϣֵ
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
    }

private:
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];

    // ѭ������
    uint32_t rotateLeft(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    // ��������
    uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | ((~x) & z);
    }

    // �û�����
    uint32_t P0(uint32_t x) {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
    }

    uint32_t P1(uint32_t x) {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
    }

    void processBlock(const unsigned char* block) {
        uint32_t W[68];
        uint32_t W1[64];

        // ��Ϣ��չ
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ rotateLeft(W[i - 3], 15)) ^
                rotateLeft(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }

        // ѹ������
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + rotateLeft(0x79CC4519, j), 7);
            uint32_t SS2 = SS1 ^ rotateLeft(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }
};

// ���Ժ���
void testSM3() {
    SM3 sm3;
    unsigned char digest[32];

    // ���Կ��ַ���
    sm3.final(digest);
    std::cout << "SM3(\"\") = ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::endl;

    // ����"abc"
    sm3.reset();
    sm3.update((const unsigned char*)"abc", 3);
    sm3.final(digest);
    std::cout << "SM3(\"abc\") = ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::endl;

    // ���Գ��ַ���
    sm3.reset();
    std::string longStr(1000000, 'a'); // 1�����'a'
    sm3.update((const unsigned char*)longStr.c_str(), longStr.size());
    sm3.final(digest);
    std::cout << "SM3(\"a\" * 1000000) = ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::endl;
}

// ���ܲ���
void performanceTest() {
    SM3 sm3;
    const int size = 1024 * 1024 * 100; // 100MB
    unsigned char* data = new unsigned char[size];
    memset(data, 0x61, size); // ���'a'

    auto start = std::chrono::high_resolution_clock::now();
    sm3.update(data, size);
    unsigned char digest[32];
    sm3.final(digest);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double speed = (double)size / (1024 * 1024) / (duration / 1000.0);

    std::cout << "Hashing 100MB data took " << duration << " ms, speed: " << speed << " MB/s" << std::endl;

    delete[] data;
}


// SM3�Ż�ʵ��
class SM3_Optimized {
public:
    SM3_Optimized() {
        reset();
    }

    void reset() {
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;
        count = 0;
    }

    void update(const unsigned char* data, size_t len) {
        size_t index = count % 64;
        count += len;

        // ���������е�����
        if (index + len < 64) {
            memcpy(buffer + index, data, len);
            return;
        }

        // ��仺����������
        memcpy(buffer + index, data, 64 - index);
        processBlock(buffer);

        // ���������Ŀ�
        size_t i = 64 - index;
        for (; i + 64 <= len; i += 64) {
            processBlock(data + i);
        }

        // ����ʣ������
        memcpy(buffer, data + i, len - i);
    }

    void final(unsigned char digest[32]) {
        size_t index = count % 64;
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);

        // ������
        unsigned char padding[64] = { 0 };
        padding[0] = 0x80;
        update(padding, padLen);

        // ��ӳ���
        uint64_t bitCount = count * 8;
        for (int i = 0; i < 8; ++i) {
            padding[i] = (bitCount >> ((7 - i) * 8)) & 0xFF;
        }
        update(padding, 8);

        // �����ϣֵ
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
    }

private:
    alignas(32) uint32_t state[8];
    uint64_t count;
    alignas(32) unsigned char buffer[64];

    // ѭ������ - ʹ�����������������
    inline uint32_t rotateLeft(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    // �������� - ʹ�����������������
    inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    // �û����� - ʹ�����������������
    inline uint32_t P0(uint32_t x) {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
    }

    // ����� - ʹ��չ��ѭ���;ֲ������Ż�
    void processBlock(const unsigned char* block) {
        alignas(32) uint32_t W[68];
        alignas(32) uint32_t W1[64];

        // ��Ϣ��չ - չ������ѭ��
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        // չ������ѭ����ʹ�þֲ�����
        for (int i = 16; i < 68; ++i) {
            uint32_t tmp = W[i - 16] ^ W[i - 9] ^ rotateLeft(W[i - 3], 15);
            W[i] = P1(tmp) ^ rotateLeft(W[i - 13], 7) ^ W[i - 6];
        }

        // ���м���W1
        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }

        // ѹ������ - ʹ�þֲ����������ڴ����
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // չ������ѭ��
        for (int j = 0; j < 16; ++j) {
            uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + rotateLeft(0x79CC4519, j), 7);
            uint32_t SS2 = SS1 ^ rotateLeft(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        for (int j = 16; j < 64; ++j) {
            uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + rotateLeft(0x7A879D8A, j - 16), 7);
            uint32_t SS2 = SS1 ^ rotateLeft(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }
};

// �Ƚ�����
void comparePerformance() {
    const int size = 1024 * 1024 * 100; // 100MB
    unsigned char* data = new unsigned char[size];
    memset(data, 0x61, size); // ���'a'

    // ���Ի���ʵ��
    {
        SM3 sm3;
        auto start = std::chrono::high_resolution_clock::now();
        sm3.update(data, size);
        unsigned char digest[32];
        sm3.final(digest);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double speed = (double)size / (1024 * 1024) / (duration / 1000.0);
        std::cout << "Basic SM3: " << duration << " ms, speed: " << speed << " MB/s" << std::endl;
    }

    // �����Ż�ʵ��
    {
        SM3_Optimized sm3;
        auto start = std::chrono::high_resolution_clock::now();
        sm3.update(data, size);
        unsigned char digest[32];
        sm3.final(digest);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double speed = (double)size / (1024 * 1024) / (duration / 1000.0);
        std::cout << "Optimized SM3: " << duration << " ms, speed: " << speed << " MB/s" << std::endl;
    }

    delete[] data;
}

int main() {
    testSM3();
    performanceTest();
    comparePerformance();
    return 0;
}