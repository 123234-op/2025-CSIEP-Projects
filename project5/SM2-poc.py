from hashlib import sha256
from ecdsa import ellipticcurve, numbertheory, SigningKey
from ecdsa.curves import Curve
import random
import binascii

# SM2参数定义
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

# 创建SM2曲线
curve_sm2 = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curve_sm2, Gx, Gy, n)


# SM3哈希函数简化实现
def sm3_hash(msg):
    return sha256(msg).digest()


# 密钥生成
def generate_key():
    private_key = random.randrange(1, n)
    public_key = private_key * generator
    return private_key, public_key


# SM2签名
def sm2_sign(private_key, msg, IDA, ENTLA, forced_k=None):
    # 计算ZA
    za_input = f"{ENTLA}{IDA}{a}{b}{Gx}{Gy}".encode()
    if isinstance(msg, str):
        msg = msg.encode()
    za = sm3_hash(za_input + msg)
    M = za + msg if isinstance(msg, bytes) else za + msg.encode()

    while True:
        k = forced_k if forced_k is not None else random.randrange(1, n)
        kG = k * generator
        x1 = kG.x()
        e = int.from_bytes(sm3_hash(M), 'big') % n
        r = (e + x1) % n
        if r == 0 or (r + k) == n:
            if forced_k is not None:
                raise ValueError("Invalid forced_k value")
            continue

        # 计算 (1 + d)^-1 mod n
        inv = numbertheory.inverse_mod(1 + private_key, n)
        s = (inv * (k - r * private_key)) % n
        if s == 0:
            if forced_k is not None:
                raise ValueError("Invalid forced_k value")
            continue

        return (r, s)


# SM2验证
def sm2_verify(public_key, msg, signature, IDA, ENTLA):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    # 计算ZA
    za_input = f"{ENTLA}{IDA}{a}{b}{Gx}{Gy}".encode()
    if isinstance(msg, str):
        msg = msg.encode()
    za = sm3_hash(za_input + msg)
    M = za + msg if isinstance(msg, bytes) else za + msg.encode()
    e = int.from_bytes(sm3_hash(M), 'big') % n

    t = (r + s) % n
    if t == 0:
        return False

    point = s * generator + t * public_key
    R = (e + point.x()) % n

    return R == r


# 1. 从泄露的k恢复私钥
def recover_private_key_from_k(signature, msg, k, IDA, ENTLA):
    r, s = signature
    za_input = f"{ENTLA}{IDA}{a}{b}{Gx}{Gy}".encode()
    if isinstance(msg, str):
        msg = msg.encode()
    za = sm3_hash(za_input + msg)
    M = za + msg if isinstance(msg, bytes) else za + msg.encode()
    e = int.from_bytes(sm3_hash(M), 'big') % n

    numerator = (k - s) % n
    denominator = (s + r) % n
    inv_denominator = numbertheory.inverse_mod(denominator, n)
    d = (numerator * inv_denominator) % n

    return d


# 2. 从重用k的两个签名恢复私钥
def recover_private_key_from_reused_k(signature1, msg1, signature2, msg2, IDA, ENTLA):
    r1, s1 = signature1
    r2, s2 = signature2

    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    inv_denominator = numbertheory.inverse_mod(denominator, n)
    d = (numerator * inv_denominator) % n

    return d


# 3. 不同用户使用相同k时恢复私钥
def recover_private_key_from_shared_k(signature, msg, k, IDA, ENTLA):
    r, s = signature
    numerator = (k - s) % n
    denominator = (s + r) % n
    inv_denominator = numbertheory.inverse_mod(denominator, n)
    d = (numerator * inv_denominator) % n
    return d


# 测试用例
def test_signature_misuse():
    print("=== 测试SM2签名误用场景 ===")

    # 公共参数
    IDA = "user123"
    ENTLA = "16"
    msg1 = "message 1"
    msg2 = "message 2"

    # 场景1: 泄露k导致私钥泄露
    print("\n1. 测试泄露k导致私钥泄露")
    private_key, public_key = generate_key()
    k = random.randrange(1, n)
    signature = sm2_sign(private_key, msg1, IDA, ENTLA, forced_k=k)
    recovered_key = recover_private_key_from_k(signature, msg1, k, IDA, ENTLA)
    print(f"原始私钥: {hex(private_key)}")
    print(f"恢复的私钥: {hex(recovered_key)}")
    print(f"恢复是否成功: {private_key == recovered_key}")

    # 场景2: 重用k导致私钥泄露
    print("\n2. 测试重用k导致私钥泄露")
    private_key, public_key = generate_key()
    k = random.randrange(1, n)
    signature1 = sm2_sign(private_key, msg1, IDA, ENTLA, forced_k=k)
    signature2 = sm2_sign(private_key, msg2, IDA, ENTLA, forced_k=k)
    recovered_key = recover_private_key_from_reused_k(signature1, msg1, signature2, msg2, IDA, ENTLA)
    print(f"原始私钥: {hex(private_key)}")
    print(f"恢复的私钥: {hex(recovered_key)}")
    print(f"恢复是否成功: {private_key == recovered_key}")

    # 场景3: 不同用户使用相同k导致私钥泄露
    print("\n3. 测试不同用户使用相同k导致私钥泄露")
    # 用户A
    private_key_A, public_key_A = generate_key()
    IDA_A = "userA"
    # 用户B
    private_key_B, public_key_B = generate_key()
    IDA_B = "userB"

    k = random.randrange(1, n)
    # 用户A签名
    signature_A = sm2_sign(private_key_A, msg1, IDA_A, ENTLA, forced_k=k)
    # 用户B签名
    signature_B = sm2_sign(private_key_B, msg2, IDA_B, ENTLA, forced_k=k)

    # 用户A恢复用户B的私钥
    recovered_key_B = recover_private_key_from_shared_k(signature_B, msg2, k, IDA_B, ENTLA)
    # 用户B恢复用户A的私钥
    recovered_key_A = recover_private_key_from_shared_k(signature_A, msg1, k, IDA_A, ENTLA)

    print(f"用户A原始私钥: {hex(private_key_A)}")
    print(f"用户B恢复的用户A私钥: {hex(recovered_key_A)}")
    print(f"恢复是否成功: {private_key_A == recovered_key_A}")
    print(f"用户B原始私钥: {hex(private_key_B)}")
    print(f"用户A恢复的用户B私钥: {hex(recovered_key_B)}")
    print(f"恢复是否成功: {private_key_B == recovered_key_B}")


if __name__ == "__main__":
    test_signature_misuse()