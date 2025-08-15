import cv2
import numpy as np
import pywt


def embed_watermark(host_img, watermark_img, alpha=0.1, level=1):
    """
    嵌入水印到宿主图像
    :param host_img: 宿主图像(BGR格式)
    :param watermark_img: 水印图像(灰度图)
    :param alpha: 水印强度系数
    :param level: DWT分解层数
    :return: 含水印的图像(BGR格式)
    """
    # 转换颜色空间为YCrCb，只在Y通道嵌入水印
    host_ycrcb = cv2.cvtColor(host_img, cv2.COLOR_BGR2YCrCb)
    Y, Cr, Cb = cv2.split(host_ycrcb)

    # 将水印调整为与Y通道相同大小
    watermark = cv2.resize(watermark_img, (Y.shape[1], Y.shape[0]))
    watermark = watermark.astype(np.float32) / 255.0

    # 对Y通道和水印进行DWT变换
    coeffs_Y = pywt.wavedec2(Y, 'haar', level=level)
    coeffs_W = pywt.wavedec2(watermark, 'haar', level=level)

    # 在低频分量中嵌入水印
    coeffs_Y_new = list(coeffs_Y)
    coeffs_Y_new[0] += alpha * coeffs_W[0]

    # 逆DWT变换
    Y_new = pywt.waverec2(coeffs_Y_new, 'haar')

    # 确保数据在有效范围内
    Y_new = np.clip(Y_new, 0, 255).astype(np.uint8)

    # 合并通道并转换回BGR
    merged = cv2.merge([Y_new, Cr, Cb])
    watermarked_img = cv2.cvtColor(merged, cv2.COLOR_YCrCb2BGR)

    return watermarked_img


def create_sample_images():
    # 创建示例宿主图像(512x512彩色渐变图)
    host_img = np.zeros((512, 512, 3), dtype=np.uint8)
    for i in range(512):
        host_img[:, i, 0] = i // 2  # 蓝色通道渐变
        host_img[i, :, 2] = i // 2  # 红色通道渐变

    # 创建示例水印(128x128黑白文字)
    watermark_img = np.zeros((128, 128), dtype=np.uint8)
    cv2.putText(watermark_img, "TEST", (20, 80),
                cv2.FONT_HERSHEY_SIMPLEX, 2, 255, 3)

    cv2.imwrite('host_image.jpg', host_img)
    cv2.imwrite('watermark.png', watermark_img)


# 在main()前调用
create_sample_images()
def extract_watermark(watermarked_img, original_img, alpha=0.1, level=1):
    """
    从含水印图像中提取水印
    :param watermarked_img: 含水印图像(BGR格式)
    :param original_img: 原始宿主图像(BGR格式)
    :param alpha: 水印强度系数(需与嵌入时相同)
    :param level: DWT分解层数(需与嵌入时相同)
    :return: 提取的水印图像(灰度图)
    """
    # 转换颜色空间为YCrCb
    wm_ycrcb = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YCrCb)
    orig_ycrcb = cv2.cvtColor(original_img, cv2.COLOR_BGR2YCrCb)

    # 获取Y通道
    Y_wm, _, _ = cv2.split(wm_ycrcb)
    Y_orig, _, _ = cv2.split(orig_ycrcb)

    # DWT变换
    coeffs_wm = pywt.wavedec2(Y_wm, 'haar', level=level)
    coeffs_orig = pywt.wavedec2(Y_orig, 'haar', level=level)

    # 提取水印
    watermark_coeff = (coeffs_wm[0] - coeffs_orig[0]) / alpha

    # 创建只有低频分量的系数列表
    coeffs_watermark = [watermark_coeff]
    for i in range(1, len(coeffs_wm)):
        coeffs_watermark.append((None, None, None))

    # 逆DWT变换
    watermark = pywt.waverec2(coeffs_watermark, 'haar')

    # 归一化并转换为8位图像
    watermark = (watermark - watermark.min()) / (watermark.max() - watermark.min())
    watermark = (watermark * 255).astype(np.uint8)

    return watermark


def robustness_test(original_img, watermarked_img, watermark_img, output_dir="output"):
    """
    水印鲁棒性测试
    :param original_img: 原始图像
    :param watermarked_img: 含水印图像
    :param watermark_img: 原始水印图像
    :param output_dir: 输出目录
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    # 保存原始水印
    cv2.imwrite(f"{output_dir}/original_watermark.png", watermark_img)

    # 1. 旋转测试
    angles = [15, 30, 45]
    for angle in angles:
        # 获取旋转矩阵
        M = cv2.getRotationMatrix2D((watermarked_img.shape[1] // 2, watermarked_img.shape[0] // 2), angle, 1)
        rotated = cv2.warpAffine(watermarked_img, M, (watermarked_img.shape[1], watermarked_img.shape[0]))

        # 提取水印
        extracted = extract_watermark(rotated, original_img)

        # 保存结果
        cv2.imwrite(f"{output_dir}/rotated_{angle}.png", rotated)
        cv2.imwrite(f"{output_dir}/extracted_rotated_{angle}.png", extracted)

    # 2. 平移测试
    shifts = [(50, 50), (100, 0), (0, 100)]
    for dx, dy in shifts:
        M = np.float32([[1, 0, dx], [0, 1, dy]])
        shifted = cv2.warpAffine(watermarked_img, M, (watermarked_img.shape[1], watermarked_img.shape[0]))

        extracted = extract_watermark(shifted, original_img)

        cv2.imwrite(f"{output_dir}/shifted_{dx}_{dy}.png", shifted)
        cv2.imwrite(f"{output_dir}/extracted_shifted_{dx}_{dy}.png", extracted)

    # 3. 裁剪测试
    crop_percents = [0.1, 0.2, 0.3]
    for percent in crop_percents:
        h, w = watermarked_img.shape[:2]
        cropped = watermarked_img[int(h * percent):h - int(h * percent), int(w * percent):w - int(w * percent)]
        cropped = cv2.resize(cropped, (w, h))

        extracted = extract_watermark(cropped, original_img)

        cv2.imwrite(f"{output_dir}/cropped_{int(percent * 100)}.png", cropped)
        cv2.imwrite(f"{output_dir}/extracted_cropped_{int(percent * 100)}.png", extracted)

    # 4. 对比度调整
    contrasts = [1.5, 2.0, 0.5]
    for contrast in contrasts:
        adjusted = cv2.convertScaleAbs(watermarked_img, alpha=contrast, beta=0)

        extracted = extract_watermark(adjusted, original_img)

        cv2.imwrite(f"{output_dir}/contrast_{contrast}.png", adjusted)
        cv2.imwrite(f"{output_dir}/extracted_contrast_{contrast}.png", extracted)

    # 5. 噪声添加
    noise_types = ['gaussian', 'salt_pepper']
    for noise_type in noise_types:
        noisy = watermarked_img.copy()
        if noise_type == 'gaussian':
            mean = 0
            var = 0.01
            sigma = var ** 0.5
            gauss = np.random.normal(mean, sigma, watermarked_img.shape)
            noisy = np.clip(watermarked_img + gauss * 255, 0, 255).astype(np.uint8)
        elif noise_type == 'salt_pepper':
            s_vs_p = 0.5
            amount = 0.05
            # 盐噪声
            num_salt = np.ceil(amount * watermarked_img.size * s_vs_p)
            coords = [np.random.randint(0, i - 1, int(num_salt)) for i in watermarked_img.shape]
            noisy[coords[0], coords[1], :] = 255
            # 椒噪声
            num_pepper = np.ceil(amount * watermarked_img.size * (1. - s_vs_p))
            coords = [np.random.randint(0, i - 1, int(num_pepper)) for i in watermarked_img.shape]
            noisy[coords[0], coords[1], :] = 0

        extracted = extract_watermark(noisy, original_img)

        cv2.imwrite(f"{output_dir}/noisy_{noise_type}.png", noisy)
        cv2.imwrite(f"{output_dir}/extracted_noisy_{noise_type}.png", extracted)

    # 6. JPEG压缩测试
    qualities = [90, 75, 50]
    for quality in qualities:
        cv2.imwrite(f"{output_dir}/temp.jpg", watermarked_img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
        compressed = cv2.imread(f"{output_dir}/temp.jpg")

        extracted = extract_watermark(compressed, original_img)

        cv2.imwrite(f"{output_dir}/jpeg_{quality}.png", compressed)
        cv2.imwrite(f"{output_dir}/extracted_jpeg_{quality}.png", extracted)

    # 清理临时文件
    if os.path.exists(f"{output_dir}/temp.jpg"):
        os.remove(f"{output_dir}/temp.jpg")


def main():
    # 读取宿主图像和水印图像
    host_img = cv2.imread('host_image.jpg')
    watermark_img = cv2.imread('watermark.png', cv2.IMREAD_GRAYSCALE)

    # 嵌入水印
    watermarked_img = embed_watermark(host_img, watermark_img, alpha=0.15, level=2)
    cv2.imwrite('watermarked_image.png', watermarked_img)

    # 提取水印(无攻击情况下)
    extracted_watermark = extract_watermark(watermarked_img, host_img, alpha=0.15, level=2)
    cv2.imwrite('extracted_watermark.png', extracted_watermark)

    # 鲁棒性测试
    robustness_test(host_img, watermarked_img, watermark_img)


if __name__ == "__main__":
    main()