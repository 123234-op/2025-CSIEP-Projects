import random
from math import gcd
from typing import Tuple


# 定义极小椭圆曲线参数
class TinyECDSA:
    def __init__(self):
        # 曲线参数: y² = x³ + 2x + 3 mod 17
        self.p = 17  # 素数域
        self.a = 2  # 曲线参数a
        self.b = 3  # 曲线参数b
        self.G = (5, 1)  # 基点
        self.n = 19  # 基点的阶

    def add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """极简椭圆曲线点加法"""
        if P is None: return Q
        if Q is None: return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None  # 无穷远点

        if P == Q:
            # 点加倍
            m = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            # 点相加
            m = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p

        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        result = None
        for _ in range(k):
            result = self.add(result, P)
        return result

    def inverse_mod(self, a: int, m: int) -> int:
        if gcd(a, m) != 1:
            return None
        return pow(a, -1, m)


def forge_signature():
    curve = TinyECDSA()

    # 1. 生成密钥对（私钥d是随机数，公钥Q = d*G）
    d = random.randint(1, curve.n - 1)
    Q = curve.mul(d, curve.G)
    print(f"真实公钥: {Q}")

    # 2. 伪造签名
    while True:
        u = random.randint(1, curve.n - 1)
        v = random.randint(1, curve.n - 1)

        # 计算 R = u*G + v*Q
        R = curve.add(curve.mul(u, curve.G), curve.mul(v, Q))
        if R is None:
            continue  # 跳过无穷远点

        r = R[0] % curve.n
        if r == 0:
            continue  # r不能为0

        try:
            v_inv = curve.inverse_mod(v, curve.n)
            if v_inv is None:
                continue

            s = (r * v_inv) % curve.n
            if s == 0:
                continue  # s不能为0

            e = (r * u * v_inv) % curve.n

            # 验证伪造的签名
            w = curve.inverse_mod(s, curve.n)
            u1 = (e * w) % curve.n
            u2 = (r * w) % curve.n
            R_prime = curve.add(curve.mul(u1, curve.G), curve.mul(u2, Q))

            if R_prime and (r == R_prime[0] % curve.n):
                print("\n成功伪造签名!")
                print(f"伪造的(r, s): ({r}, {s})")
                print(f"对应的消息哈希e: {e}")

                # 生成真实签名对比
                k = random.randint(1, curve.n - 1)
                R_real = curve.mul(k, curve.G)
                r_real = R_real[0] % curve.n
                k_inv = curve.inverse_mod(k, curve.n)
                s_real = (k_inv * (e + d * r_real)) % curve.n
                print(f"\n真实签名(r, s): ({r_real}, {s_real})")
                break
        except:
            continue


if __name__ == "__main__":
    print("使用极小参数曲线: y² = x³ + 2x + 3 mod 17")
    print("基点G = (5,1), 阶n = 19\n")
    forge_signature()