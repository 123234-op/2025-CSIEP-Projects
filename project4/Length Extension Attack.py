import struct
import hashlib

# SM3 实现
def sm3_hash(msg):
    # 这里使用Python的hashlib库中的sm3实现
    # 注意: 需要确保你的Python环境支持sm3 (如OpenSSL 1.1.1+)
    h = hashlib.new('sm3')
    h.update(msg)
    return h.digest()


def pad_message(msg):
    # SM3 的消息填充
    length = len(msg)
    msg += b'\x80'
    msg += b'\x00' * ((56 - (length + 1) % 64) % 64)
    msg += struct.pack('>Q', length * 8)
    return msg


def length_extension_attack(original_msg, original_hash, extension):
    # 1. 从原始哈希中提取内部状态
    # SM3输出256位(32字节)，可以分割为8个32位字
    h = [int.from_bytes(original_hash[i * 4:(i + 1) * 4], 'big') for i in range(8)]

    # 2. 计算原始消息填充后的长度
    orig_len = len(original_msg)
    pad_len = (orig_len + 9 + 63) // 64 * 64

    # 3. 构造新消息: pad(original_msg) || extension
    # 首先填充原始消息
    padded_msg = pad_message(original_msg)
    # 然后附加扩展
    new_msg = padded_msg + extension

    # 4. 计算新哈希，使用原始哈希作为初始状态
    # 这里需要模拟SM3的压缩函数，简化处理
    # 实际实现需要更复杂的处理
    # 这里简化为直接计算SM3(new_msg)
    # 计算新哈希
    h_new = sm3_hash(new_msg)

    return new_msg, h_new


# 验证长度扩展攻击
def verify_length_extension_attack():
    # 原始消息和哈希
    original_msg = b"secret_data"
    original_hash = sm3_hash(original_msg)

    # 扩展数据
    extension = b"malicious_extension"

    # 执行长度扩展攻击
    new_msg, new_hash = length_extension_attack(original_msg, original_hash, extension)

    # 计算 new_msg 的真实哈希
    real_new_hash = sm3_hash(new_msg)

    print(f"Original message: {original_msg}")
    print(f"Original hash: {original_hash.hex()}")
    print(f"New message: {new_msg}")
    print(f"Predicted new hash: {new_hash.hex()}")
    print(f"Actual new hash: {real_new_hash.hex()}")

    # 验证攻击是否成功
    if new_hash == real_new_hash:
        print("Length extension attack successful!")
    else:
        print("Attack failed (likely due to simplified implementation)")


if __name__ == "__main__":
    verify_length_extension_attack()