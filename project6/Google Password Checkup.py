import hashlib
from Crypto.Util.number import getPrime, getRandomRange, inverse
from Crypto.Random import get_random_bytes
from typing import List, Tuple, Set
import random
import time
import math

# 定义数据类型
Identifier = bytes
Value = int
EncryptedValue = int
GroupElement = int

class Party1:
    def __init__(self, dataset: List[Identifier]):
        self.dataset = dataset
        self.m1 = len(dataset)
        self.k1 = None
        self.intersection_size = 0
        self.intersection_sum_ciphertext = 0
        self.p = None
        self.g = None
        self.hashed_data = {}  # 存储原始标识符和哈希值的映射

    def setup(self, p: int, g: int):
        self.p = p
        self.g = g
        self.k1 = getRandomRange(1, p - 1)
        # 预计算所有哈希值
        for v in self.dataset:
            h_v = self.hash_to_group(v)
            self.hashed_data[v] = h_v

    def round1(self) -> List[Tuple[Identifier, GroupElement]]:
        #返回(原始标识符, H(v)^k1)
        round1_msg = []
        for v in self.dataset:
            h_v = self.hashed_data[v]
            h_v_k1 = pow(h_v, self.k1, self.p)
            round1_msg.append((v, h_v_k1))
        random.shuffle(round1_msg)
        return round1_msg

    def round3(self, round2_msg: Tuple[List[Tuple[GroupElement, EncryptedValue]], List[GroupElement]],
               paillier_public_key: Tuple[int, int]):
       #处理P2返回的双重加密值和加密数据
        p2_encrypted_data, p2_h_v_k1k2_list = round2_msg

        # 建立P2的双重加密值到原始标识符的映射
        p2_mapping = {}
        for v, h_v_k1 in self.round1_msg_sent:
            h_v_k1k2 = pow(h_v_k1, self.k2_received, self.p)
            p2_mapping[h_v_k1k2] = v

        # 计算交集
        intersection = set()
        sum_ct = None
        n, _ = paillier_public_key

        for h_w_k2, ct in p2_encrypted_data:
            # 计算H(w)^k1k2
            h_w_k1k2 = pow(h_w_k2, self.k1, self.p)

            if h_w_k1k2 in p2_h_v_k1k2_list:
                intersection.add(h_w_k1k2)
                if sum_ct is None:
                    sum_ct = ct
                else:
                    sum_ct = (sum_ct * ct) % (n * n)

        self.intersection_size = len(intersection)
        self.intersection_sum_ciphertext = sum_ct if sum_ct is not None else 0

    def get_results(self):
        return self.intersection_size, self.intersection_sum_ciphertext

    def hash_to_group(self, x: Identifier) -> GroupElement:
        h = hashlib.sha256(x).digest()
        h_int = int.from_bytes(h, 'big') % self.p
        return h_int if h_int != 0 else 1


class Party2:
    def __init__(self, dataset: List[Tuple[Identifier, Value]]):
        self.dataset = dataset
        self.m2 = len(dataset)
        self.k2 = None
        self.paillier_public_key = None
        self.paillier_private_key = None
        self.p = None
        self.g = None
        self.hashed_data = {}  # 存储原始标识符和哈希值的映射

    def setup(self, p: int, g: int):
        self.p = p
        self.g = g
        self.k2 = getRandomRange(1, p - 1)
        self.generate_paillier_keys(512)
        # 预计算所有哈希值
        for w, _ in self.dataset:
            h_w = self.hash_to_group(w)
            self.hashed_data[w] = h_w

    def generate_paillier_keys(self, bits: int):
        p = getPrime(bits)
        q = getPrime(bits)
        n = p * q
        lambda_n = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        g = n + 1

        g_lambda = pow(g, lambda_n, n * n)
        l_g_lambda = (g_lambda - 1) // n
        mu = inverse(l_g_lambda, n)

        self.paillier_public_key = (n, g)
        self.paillier_private_key = (lambda_n, mu)

    def paillier_encrypt(self, m: int) -> EncryptedValue:
        n, g = self.paillier_public_key
        r = getRandomRange(1, n)
        return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

    def round2(self, round1_msg: List[Tuple[Identifier, GroupElement]]) -> Tuple[
        List[Tuple[GroupElement, EncryptedValue]], List[GroupElement]]:
        # 存储P1的原始消息
        self.round1_msg_received = round1_msg

        # 1. 对P1的消息进行双重加密
        h_v_k1k2_list = []
        for v, h_v_k1 in round1_msg:
            h_v_k1k2 = pow(h_v_k1, self.k2, self.p)
            h_v_k1k2_list.append(h_v_k1k2)

        # 2. 准备自己的加密数据
        encrypted_data = []
        for w, t in self.dataset:
            h_w = self.hashed_data[w]
            h_w_k2 = pow(h_w, self.k2, self.p)
            ct = self.paillier_encrypt(t)
            encrypted_data.append((h_w_k2, ct))

        # 随机打乱
        random.shuffle(h_v_k1k2_list)
        random.shuffle(encrypted_data)

        return encrypted_data, h_v_k1k2_list

    def decrypt_sum(self, ciphertext: EncryptedValue) -> int:
        if ciphertext == 0:
            return 0

        n, _ = self.paillier_public_key
        lambda_n, mu = self.paillier_private_key

        if ciphertext >= n * n:
            raise ValueError("Invalid ciphertext")

        c_lambda = pow(ciphertext, lambda_n, n * n)
        l_c_lambda = (c_lambda - 1) // n
        return (l_c_lambda * mu) % n

    def hash_to_group(self, x: Identifier) -> GroupElement:
        h = hashlib.sha256(x).digest()
        h_int = int.from_bytes(h, 'big') % self.p
        return h_int if h_int != 0 else 1


def generate_group_parameters(bit_length: int = 256) -> Tuple[int, int]:
    p = getPrime(bit_length)
    g = 2
    while True:
        if pow(g, (p - 1) // 2, p) != 1 and pow(g, 2, p) != 1:
            break
        g += 1
    return p, g


def simulate_protocol(p1_data: List[Identifier],
                      p2_data: List[Tuple[Identifier, Value]],
                      debug: bool = True) -> Tuple[int, int]:
    print("=== 协议开始 ===")

    # 1. 生成群参数
    p, g = generate_group_parameters(256)
    if debug:
        print(f"[初始化] 群参数: p={p}, g={g}")

    # 2. 初始化双方
    p1 = Party1(p1_data)
    p2 = Party2(p2_data)
    p1.setup(p, g)
    p2.setup(p, g)

    # 3. 第一轮: P1 -> P2
    p1.round1_msg_sent = p1.round1()
    if debug:
        print(f"[第一轮] P1发送 {len(p1.round1_msg_sent)} 个(标识符, H(v)^k1)对")

    # 4. 第二轮: P2 -> P1
    p2.round2_result = p2.round2(p1.round1_msg_sent)
    p1.k2_received = p2.k2  # 模拟密钥共享

    if debug:
        print(f"[第二轮] P2发送:")
        print(f"  - {len(p2.round2_result[0])} 个(H(w)^k2, 加密值)对")
        print(f"  - {len(p2.round2_result[1])} 个H(v)^k1k2值")

    # 5. 第三轮: P1计算交集和求和
    p1.round3(p2.round2_result, p2.paillier_public_key)
    intersection_size, sum_ciphertext = p1.get_results()

    if debug:
        print(f"[第三轮] P1计算:")
        print(f"  - 交集大小: {intersection_size}")
        print(f"  - 加密的和: {sum_ciphertext if sum_ciphertext else '无'}")

    # 6. P2解密求和结果
    intersection_sum = p2.decrypt_sum(sum_ciphertext) if sum_ciphertext else 0

    if debug:
        print(f"[结果] P2解密得到:")
        print(f"  - 交集和: {intersection_sum}")

    return intersection_size, intersection_sum


def test_protocol():
    """增强的测试函数"""
    # 测试数据
    common_ids = [b"user1", b"user2", b"user3"]
    p1_ids = common_ids + [b"user4", b"user5"]
    p2_data = [(id, (i + 1) * 10) for i, id in enumerate(common_ids + [b"user6", b"user7"])]

    print("\n测试数据:")
    print("P1的数据集:", p1_ids)
    print("P2的数据集:", p2_data)
    print("预期交集:", common_ids)
    print("预期交集和:", sum(t for id, t in p2_data if id in common_ids))

    # 运行协议
    start_time = time.time()
    size, sum_ = simulate_protocol(p1_ids, p2_data)
    end_time = time.time()

    # 验证结果
    expected_size = len(common_ids)
    expected_sum = sum(t for id, t in p2_data if id in common_ids)

    print("\n协议验证:")
    print(f"交集大小: {size} | {'正确' if size == expected_size else '错误'}")
    print(f"交集和: {sum_} | {'正确' if sum_ == expected_sum else '错误'}")
    print(f"执行时间: {end_time - start_time:.2f}秒")


if __name__ == "__main__":
    test_protocol()