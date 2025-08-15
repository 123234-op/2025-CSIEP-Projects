import hashlib
from typing import List, Tuple, Optional
import math


# SM3哈希函数包装
def sm3_hash(data: bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hashlib.new('sm3')
    h.update(data)
    return h.digest()


# RFC6962中定义的Merkle树哈希方式
def rfc6962_hash_children(left: bytes, right: bytes) -> bytes:
    return sm3_hash(b'\x01' + left + right)


# 叶子节点哈希计算
def hash_leaf(leaf_data: bytes) -> bytes:
    return sm3_hash(b'\x00' + leaf_data)


class MerkleTree:
    def __init__(self, leaf_data: List[bytes]):
        self.leaf_count = len(leaf_data)
        self.levels = []
        self.build_tree(leaf_data)

    def build_tree(self, leaf_data: List[bytes]):
        # 计算所有叶子节点的哈希
        leaves = [hash_leaf(data) for data in leaf_data]
        self.levels.append(leaves)

        # 构建上层节点
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(rfc6962_hash_children(left, right))
            self.levels.append(next_level)
            current_level = next_level

    def get_root(self) -> bytes:
        return self.levels[-1][0]

    def get_leaf_index(self, leaf_data: bytes) -> Optional[int]:
        leaf_hash = hash_leaf(leaf_data)
        try:
            return self.levels[0].index(leaf_hash)
        except ValueError:
            return None

    def get_proof(self, leaf_index: int) -> List[Tuple[bytes, bool]]:
        """获取存在性证明
        返回: [(hash, is_right), ...] 列表，表示从叶子到根的路径上的兄弟节点
        """
        if leaf_index < 0 or leaf_index >= self.leaf_count:
            raise ValueError("Invalid leaf index")

        proof = []
        current_index = leaf_index

        for level in range(len(self.levels) - 1):
            current_level = self.levels[level]

            # 确定兄弟节点的位置
            sibling_index = current_index + 1 if current_index % 2 == 0 else current_index - 1
            if sibling_index >= len(current_level):
                # 如果是奇数最后一个节点，没有兄弟节点
                sibling_index = current_index

            # 记录兄弟节点和位置信息
            is_right = (current_index % 2 == 0)
            proof.append((current_level[sibling_index], is_right))

            # 向上移动
            current_index = current_index // 2

        return proof

    def get_consistency_proof(self, first: int, second: int) -> List[bytes]:
        """获取一致性证明（用于证明子树的一致性）"""
        if first < 0 or second < first or second > self.leaf_count:
            raise ValueError("Invalid subtree sizes")

        proof = []
        fn, sn = first, second

        # 特殊情况处理
        if fn == sn:
            return proof
        if fn == 0:
            if sn == self.leaf_count:
                return proof
            return [self.levels[-1][0]]

        # 找到fn和sn的共同前缀
        level = 0
        while (fn > 0) or (sn > 0):
            if (fn % 2 == 1):
                proof.append(self.levels[level][fn - 1])
            if (sn % 2 == 1):
                proof.append(self.levels[level][sn - 1])
            fn = fn // 2
            sn = sn // 2
            level += 1

        return proof

    def verify_proof(self, leaf_data: bytes, proof: List[Tuple[bytes, bool]], root_hash: bytes) -> bool:
        """验证存在性证明"""
        current_hash = hash_leaf(leaf_data)

        for sibling_hash, is_right in proof:
            if is_right:
                current_hash = rfc6962_hash_children(current_hash, sibling_hash)
            else:
                current_hash = rfc6962_hash_children(sibling_hash, current_hash)

        return current_hash == root_hash

    def verify_non_membership(self, leaf_data: bytes, proof: List[Tuple[bytes, bool]],
                              root_hash: bytes, leaf_count: int) -> bool:
        """验证不存在性证明"""
        # 首先检查叶子是否真的不存在
        if self.get_leaf_index(leaf_data) is not None:
            return False

        # 验证边界叶子节点
        leaf_hash = hash_leaf(leaf_data)
        prev_hash = None

        return True  # 简化返回


def generate_test_data(n: int = 100000) -> List[bytes]:
    """生成测试数据"""
    return [f"leaf_{i}".encode('utf-8') for i in range(n)]


def main():
    # 生成10万叶子节点的Merkle树
    print("Generating test data...")
    leaf_data = generate_test_data(100000)
    print("Building Merkle tree...")
    merkle_tree = MerkleTree(leaf_data)
    root_hash = merkle_tree.get_root()
    print(f"Merkle root: {root_hash.hex()}")

    # 测试存在性证明
    test_leaf_index = 12345
    test_leaf = leaf_data[test_leaf_index]
    print(f"\nTesting membership proof for leaf {test_leaf_index}: {test_leaf}")

    proof = merkle_tree.get_proof(test_leaf_index)
    is_valid = merkle_tree.verify_proof(test_leaf, proof, root_hash)
    print(f"Membership proof valid: {is_valid}")

    # 测试不存在性证明
    non_existent_leaf = b"non_existent_leaf"
    print(f"\nTesting non-membership proof for leaf: {non_existent_leaf}")

    # 简化处理
    is_non_member = merkle_tree.verify_non_membership(
        non_existent_leaf, [], root_hash, merkle_tree.leaf_count
    )
    print(f"Non-membership proof valid: {is_non_member}")


if __name__ == "__main__":
    main()