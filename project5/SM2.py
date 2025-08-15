import random
import hashlib
import binascii
from math import log, ceil
import time

# 使用SM2推荐参数
class SM2:
    def __init__(self):
        # 椭圆曲线参数 (SM2推荐参数)
        # p: 椭圆曲线有限域的素数
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        # a: 椭圆曲线方程参数 y² = x³ + ax + b
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        # b: 椭圆曲线方程参数 y² = x³ + ax + b
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        # n: 基点G的阶
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        # Gx: 基点G的x坐标
        self.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        # Gy: 基点G的y坐标
        self.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        # G: 基点，表示为元组(x, y)
        self.G = (self.Gx, self.Gy)

    # 扩展欧几里得算法求模逆
    # 计算a在模n下的乘法逆元，即a^(-1) mod n
    def inv(self, a, n):
        def ext_gcd(a, b, arr):
            if b == 0:
                arr[0] = 1
                arr[1] = 0
                return a
            g = ext_gcd(b, a % b, arr)
            t = arr[0]
            arr[0] = arr[1]
            arr[1] = t - (a // b) * arr[1]
            return g

        arr = [0, 1]
        gcd = ext_gcd(a, n, arr)
        if gcd == 1:
            return (arr[0] % n + n) % n
        else:
            return -1

    # 椭圆曲线点加运算
    # 计算椭圆曲线上两点P和Q的和，即P + Q
    def add(self, P, Q):
        if P == 0 and Q == 0:
            return 0
        elif P == 0:
            return Q
        elif Q == 0:
            return P
        else:
            # 如果两点x坐标相同但y坐标不同，则它们的和是无穷远点
            if P[0] == Q[0] and P[1] != Q[1]:
                return 0
            # 点加公式
            if P != Q:
                l = ((Q[1] - P[1]) * self.inv(Q[0] - P[0], self.p)) % self.p
            else:
                # 倍点公式
                l = ((3 * P[0] * P[0] + self.a) * self.inv(2 * P[1], self.p)) % self.p
            x = (l * l - P[0] - Q[0]) % self.p
            y = (l * (P[0] - x) - P[1]) % self.p
            return (x, y)

    # 椭圆曲线点乘运算（快速幂算法）
    # 计算标量k与点P的乘积，即kP
    def multiply(self, k, P):
        k = k % self.n
        if k == 0:
            return 0
        elif k == 1:
            return P

        Q = 0
        # 使用快速幂算法进行点乘运算
        while k > 0:
            if k & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
            k >>= 1
        return Q

    # 生成SM2密钥对
    # 返回私钥和对应的公钥
    def generate_keypair(self):
        private_key = random.randint(1, self.n - 1)
        public_key = self.multiply(private_key, self.G)
        return private_key, public_key

    # 计算Z值（签名和验证过程中的中间值）
    # Z = SM3(ENTL || ID || a || b || Gx || Gy || xA || yA)
    def compute_z(self, user_id, public_key):
        # 用户ID的比特长度
        entl = len(user_id) * 8
        # 转换为字节串
        user_id_bytes = user_id.encode('utf-8')
        # 计算哈希
        m = hashlib.sha256()
        m.update(bytes([entl >> 8 & 0xff]))
        m.update(bytes([entl & 0xff]))
        m.update(user_id_bytes)
        m.update(bytes.fromhex("%064x" % self.a))
        m.update(bytes.fromhex("%064x" % self.b))
        m.update(bytes.fromhex("%064x" % self.Gx))
        m.update(bytes.fromhex("%064x" % self.Gy))
        m.update(bytes.fromhex("%064x" % public_key[0]))
        m.update(bytes.fromhex("%064x" % public_key[1]))
        return int(m.hexdigest(), 16)

    # SM2数字签名算法
    # 使用私钥对消息进行签名，返回签名值(r, s)
    def sign(self, message, private_key, user_id, public_key):
        z = self.compute_z(user_id, public_key)
        m_ = (z << (ceil(log(z, 2) / 8) * 8)) | int.from_bytes(message.encode('utf-8'), 'big')
        e = hashlib.sha256(m_.to_bytes((m_.bit_length() + 7) // 8, 'big')).hexdigest()
        e = int(e, 16)

        while True:
            k = random.randint(1, self.n - 1)
            P = self.multiply(k, self.G)
            r = (e + P[0]) % self.n
            if r == 0 or r + k == self.n:
                continue
            s = (self.inv(1 + private_key, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                continue
            break
        return (r, s)

    # SM2签名验证算法
    # 使用公钥验证签名的有效性，返回True或False
    def verify(self, message, signature, public_key, user_id):
        r, s = signature
        # 检查签名值r和s是否在有效范围内
        if not (1 <= r <= self.n - 1 and 1 <= s <= self.n - 1):
            return False

        z = self.compute_z(user_id, public_key)
        m_ = (z << (ceil(log(z, 2) / 8) * 8)) | int.from_bytes(message.encode('utf-8'), 'big')
        e = hashlib.sha256(m_.to_bytes((m_.bit_length() + 7) // 8, 'big')).hexdigest()
        e = int(e, 16)

        t = (r + s) % self.n
        if t == 0:
            return False

        P = self.add(self.multiply(s, self.G), self.multiply(t, public_key))
        if P == 0:
            return False

        R = (e + P[0]) % self.n
        return R == r

    # SM2公钥加密算法
    # 使用公钥对明文进行加密，返回密文(C1 || C3 || C2)
    def encrypt(self, plaintext, public_key):
        msg = plaintext.encode('utf-8')
        k = random.randint(1, self.n - 1)
        C1 = self.multiply(k, self.G)
        C1_bytes = bytes.fromhex("%064x" % C1[0]) + bytes.fromhex("%064x" % C1[1])

        S = self.multiply(k, public_key)
        x2 = S[0]
        y2 = S[1]
        x2_bytes = bytes.fromhex("%064x" % x2)
        y2_bytes = bytes.fromhex("%064x" % y2)

        # KDF密钥派生函数
        klen = len(msg) * 8
        ct = 0x00000001
        K = b''
        while len(K) * 8 < klen:
            m = hashlib.sha256()
            m.update(x2_bytes)
            m.update(y2_bytes)
            m.update(ct.to_bytes(4, 'big'))
            K += m.digest()
            ct += 1
        K = K[:len(msg)]

        # 异或加密
        C2 = bytes([a ^ b for a, b in zip(msg, K)])

        # 计算C3 (MAC)
        m = hashlib.sha256()
        m.update(x2_bytes)
        m.update(msg)
        m.update(y2_bytes)
        C3 = m.digest()

        return C1_bytes + C3 + C2

    # SM2私钥解密算法
    # 使用私钥对密文进行解密，返回明文
    def decrypt(self, ciphertext, private_key):
        C1_bytes = ciphertext[:64]
        C3 = ciphertext[64:96]
        C2 = ciphertext[96:]

        x = int.from_bytes(C1_bytes[:32], 'big')
        y = int.from_bytes(C1_bytes[32:], 'big')
        C1 = (x, y)

        S = self.multiply(private_key, C1)
        x2 = S[0]
        y2 = S[1]
        x2_bytes = bytes.fromhex("%064x" % x2)
        y2_bytes = bytes.fromhex("%064x" % y2)

        # KDF密钥派生函数
        klen = len(C2) * 8
        ct = 0x00000001
        K = b''
        while len(K) * 8 < klen:
            m = hashlib.sha256()
            m.update(x2_bytes)
            m.update(y2_bytes)
            m.update(ct.to_bytes(4, 'big'))
            K += m.digest()
            ct += 1
        K = K[:len(C2)]

        # 异或解密
        msg = bytes([a ^ b for a, b in zip(C2, K)])

        # 验证C3
        m = hashlib.sha256()
        m.update(x2_bytes)
        m.update(msg)
        m.update(y2_bytes)
        u = m.digest()
        if u != C3:
            raise ValueError("Decryption failed: MAC verification failed")

        return msg.decode('utf-8')


# SM2改进版本1：使用预计算表加速点乘运算
class SM2_Improved1(SM2):
    def __init__(self):
        super().__init__()
        # 预计算表
        self.precompute_table = {}
        self.build_precompute_table()

    # 构建预计算表
    # 预计算2^i * G，加速基点乘法运算
    def build_precompute_table(self):
        # 预计算2^i * G
        table = {}
        table[0] = self.G
        for i in range(1, 256):
            table[i] = self.add(table[i - 1], table[i - 1])
        self.precompute_table = table

    # 改进的点乘运算
    # 如果是基点G，使用预计算表加速；否则使用普通点乘
    def multiply(self, k, P):
        # 如果是基点G，使用预计算表加速
        if P == self.G:
            Q = 0
            for i in range(256):
                if k & (1 << i):
                    Q = self.add(Q, self.precompute_table[i])
            return Q
        else:
            # 普通点乘
            return super().multiply(k, P)


# SM2改进版本2：使用窗口法加速点乘运算
class SM2_Improved2(SM2):
    def __init__(self, window_size=4):
        super().__init__()
        self.window_size = window_size

    # 使用窗口法进行点乘运算
    # 通过预计算窗口值减少点加次数，提高运算效率
    def multiply(self, k, P):
        k = k % self.n
        if k == 0:
            return 0
        elif k == 1:
            return P

        # 预计算窗口
        window = [0] * (1 << self.window_size)
        window[0] = 0
        window[1] = P
        for i in range(2, 1 << self.window_size):
            window[i] = self.add(window[i - 1], P)

        # 窗口法计算
        Q = 0
        i = ceil(log(k, 2))
        while i >= 0:
            if Q != 0:
                for _ in range(self.window_size):
                    Q = self.add(Q, Q)

            window_bits = 0
            for j in range(self.window_size):
                if i - j >= 0 and (k & (1 << (i - j))):
                    window_bits |= (1 << j)

            if window_bits > 0:
                Q = self.add(Q, window[window_bits])

            i -= self.window_size

        return Q


# SM2改进版本3：使用Montgomery阶梯算法防止侧信道攻击
class SM2_Improved3(SM2):
    # Montgomery阶梯算法实现点乘运算
    # 防止时序攻击和简单功耗分析，提高安全性
    def multiply(self, k, P):
        # Montgomery阶梯算法，防止时序攻击和简单功耗分析
        k = k % self.n
        if k == 0:
            return 0
        elif k == 1:
            return P

        R0 = 0
        R1 = P

        for i in range(ceil(log(k, 2)), -1, -1):
            if (k >> i) & 1:
                R0 = self.add(R0, R1)
                R1 = self.add(R1, R1)
            else:
                R1 = self.add(R0, R1)
                R0 = self.add(R0, R0)

        return R0


# SM2改进版本4：支持多种哈希算法
class SM2_Improved4(SM2):
    def __init__(self, hash_func='sha256'):
        super().__init__()
        self.hash_func = hash_func

    # 支持多种哈希算法的Z值计算
    # 可选择sha256、sha3_256或blake2s作为哈希函数
    def compute_z(self, user_id, public_key):
        entl = len(user_id) * 8
        user_id_bytes = user_id.encode('utf-8')

        if self.hash_func == 'sha256':
            m = hashlib.sha256()
        elif self.hash_func == 'sha3_256':
            m = hashlib.sha3_256()
        elif self.hash_func == 'blake2s':
            m = hashlib.blake2s(digest_size=32)
        else:
            raise ValueError("Unsupported hash function")

        m.update(bytes([entl >> 8 & 0xff]))
        m.update(bytes([entl & 0xff]))
        m.update(user_id_bytes)
        m.update(bytes.fromhex("%064x" % self.a))
        m.update(bytes.fromhex("%064x" % self.b))
        m.update(bytes.fromhex("%064x" % self.Gx))
        m.update(bytes.fromhex("%064x" % self.Gy))
        m.update(bytes.fromhex("%064x" % public_key[0]))
        m.update(bytes.fromhex("%064x" % public_key[1]))
        return int(m.hexdigest(), 16)


if __name__ == "__main__":
    # 测试基础实现
    sm2 = SM2()
    private_key, public_key = sm2.generate_keypair()
    user_id = "alice@example.com"
    message = "Hello, SM2!"

    print("Testing basic SM2 implementation:")
    print(f"Private key: {hex(private_key)}")
    print(f"Public key: ({hex(public_key[0])}, {hex(public_key[1])})")

    # 签名验证测试
    signature = sm2.sign(message, private_key, user_id, public_key)
    print(f"Signature: (r={hex(signature[0])}, s={hex(signature[1])})")
    verified = sm2.verify(message, signature, public_key, user_id)
    print(f"Signature verified: {verified}")

    # 加密解密测试
    ciphertext = sm2.encrypt(message, public_key)
    decrypted = sm2.decrypt(ciphertext, private_key)
    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted}")

    # 测试改进版本
    print("\nTesting improved versions:")

    # 测试预计算表改进
    sm2_imp1 = SM2_Improved1()
    start = time.time()
    for _ in range(100):
        sm2.multiply(private_key, sm2.G)
    print(f"Original multiply time: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        sm2_imp1.multiply(private_key, sm2_imp1.G)
    print(f"Precomputed multiply time: {time.time() - start:.4f}s")

    # 测试窗口法改进
    sm2_imp2 = SM2_Improved2(window_size=4)
    start = time.time()
    for _ in range(100):
        sm2_imp2.multiply(private_key, sm2_imp2.G)
    print(f"Window method (w=4) multiply time: {time.time() - start:.4f}s")

    # 测试Montgomery阶梯
    sm2_imp3 = SM2_Improved3()
    start = time.time()
    for _ in range(100):
        sm2_imp3.multiply(private_key, sm2_imp3.G)
    print(f"Montgomery ladder multiply time: {time.time() - start:.4f}s")

    # 测试不同哈希算法
    sm2_imp4_sha256 = SM2_Improved4('sha256')
    sm2_imp4_sha3 = SM2_Improved4('sha3_256')
    sm2_imp4_blake = SM2_Improved4('blake2s')

    start = time.time()
    for _ in range(1000):
        sm2_imp4_sha256.compute_z(user_id, public_key)
    print(f"SHA256 compute_z time: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000):
        sm2_imp4_sha3.compute_z(user_id, public_key)
    print(f"SHA3-256 compute_z time: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000):
        sm2_imp4_blake.compute_z(user_id, public_key)
    print(f"BLAKE2s compute_z time: {time.time() - start:.4f}s")
