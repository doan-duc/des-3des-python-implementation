from typing import List, Tuple
import time

# BẢNG PC-1: Hoán vị và loại bit chẵn lẻ (64-bit -> 56-bit)
# Bảng PC-1: chọn 56 bit có nghĩa từ 64-bit khóa gốc.
# Số thứ tự bit theo quy ước 1-indexed từ MSB (bit 1 = bit cao nhất).
# Các bit 8, 16, 24, 32, 40, 48, 56, 64 là bit chẵn lẻ, bị loại bỏ.
PC1: List[int] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]
# Sau PC-1 thu được 56-bit, chia đôi:
#   C0 = 28 bit cao (hàng 1–4 của PC-1)
#   D0 = 28 bit thấp (hàng 5–8 của PC-1)

# BẢNG PC-2: Nén 56-bit xuống 48-bit cho mỗi subkey
# Bảng PC-2: chọn 48 bit từ 56-bit (sau khi ghép C và D).
PC2: List[int] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Số bit dịch vòng trái cho mỗi vòng
# Vòng 1, 2, 9, 16 -> dịch 1 bit; các vòng còn lại -> dịch 2 bit.
SHIFT_SCHEDULE: List[int] = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
]


# HÀM XỬ LÝ BIT CƠ BẢN
def apply_permutation(bits: int, table: List[int], input_size: int) -> int:
    # Áp dụng bảng hoán vị lên một số nguyên biểu diễn chuỗi bit.
  
    result = 0
    output_size = len(table)
    for i in range(output_size):
        bit_pos = table[i]                     # Vị trí bit cần lấy (1-indexed)
        shift_in = input_size - bit_pos        # Số bit phải dịch phải để lấy bit đó
        bit_val = (bits >> shift_in) & 1       # Giá trị bit tại vị trí đó (0 hoặc 1)
        shift_out = output_size - 1 - i        # Vị trí bit trong kết quả đầu ra
        result |= (bit_val << shift_out)       # Đặt bit vào đúng vị trí kết quả
    return result


def left_circular_shift_28(value: int, shift: int) -> int:
    # Dịch bit vòng trái cho số nguyên 28-bit.

    mask_28 = 0xFFFFFFF   # Mặt nạ 28-bit (28 bit thấp = 1)
    shifted = ((value << shift) | (value >> (28 - shift))) & mask_28
    return shifted

#  HÀM SINH 16 SUBKEYS CHÍNH

def generate_subkeys(key: int, verbose: bool = False) -> List[int]:
    
    # Sinh ra 16 subkeys 48-bit từ một khóa DES 64-bit.

    if verbose:
        print(f"\n  Khóa gốc (64-bit hex) : {format(key, '016X')}")
        print(f"  Khóa gốc (nhị phân)   : {format(key, '064b')}")

    #  Bước 1: PC-1 (64-bit -> 56-bit) 
    key_56 = apply_permutation(key, PC1, input_size=64)
    if verbose:
        print(f"\n  Sau PC-1  (56-bit hex): {format(key_56, '014X')}")

    #  Bước 2: Tách C0 và D0 
    C = (key_56 >> 28) & 0xFFFFFFF   # 28 bit cao
    D = key_56 & 0xFFFFFFF           # 28 bit thấp
    if verbose:
        print(f"  C0 (28-bit): {format(C, '07X')}   "
              f"D0 (28-bit): {format(D, '07X')}")
        print(f"\n  {'Vòng':<6} {'Dịch':<6} {'C (hex)':<10} "
              f"{'D (hex)':<10} {'Subkey (hex)':<14}")
        print("  " + "-" * 52)

    subkeys: List[int] = []

    #  Bước 3: 16 vòng sinh subkey 
    for rnd in range(16):
        shift = SHIFT_SCHEDULE[rnd]

        # 3a: Dịch vòng trái C và D
        C = left_circular_shift_28(C, shift)
        D = left_circular_shift_28(D, shift)

        # 3b: Ghép C || D thành 56-bit
        CD = (C << 28) | D

        # 3c: PC-2 (56-bit → 48-bit) = subkey của vòng này
        subkey = apply_permutation(CD, PC2, input_size=56)
        subkeys.append(subkey)

        if verbose:
            print(f"  {rnd + 1:<6} {shift:<6} {format(C, '07X'):<10} "
                  f"{format(D, '07X'):<10} {format(subkey, '012X')}")

    return subkeys


def generate_subkeys_from_deskey(des_key: object, verbose: bool = False) -> List[int]:
    
    # nhận DESKey (từ module1) -> 16 subkeys.
    # Truy cập thuộc tính .value của DESKey
    key_int: int = getattr(des_key, 'value', 0)
    return generate_subkeys(key_int, verbose=verbose)


#  SINH SUBKEYS CHO 3DES (3 BỘ SUBKEYS)
def generate_all_3des_subkeys(
    triple_key: object,
    verbose: bool = False,
) -> Tuple[List[int], List[int], List[int], float]:
    #Sinh 3 bộ subkeys đầy đủ cho 3DES từ TripleDESKey.

    k1_val: int = getattr(getattr(triple_key, 'k1', None), 'value', 0)
    k2_val: int = getattr(getattr(triple_key, 'k2', None), 'value', 0)

    # get_k3() trả về DESKey hoặc k1 (2TDEA)
    k3_obj = None
    get_k3_fn = getattr(triple_key, 'get_k3', None)
    if callable(get_k3_fn):
        k3_obj = get_k3_fn()
    k3_val: int = getattr(k3_obj, 'value', k1_val)

    if verbose:
        print(f"\n  === SINH SUBKEYS CHO 3DES ===")
        print(f"  K1: {format(k1_val, '016X')}")
        print(f"  K2: {format(k2_val, '016X')}")
        print(f"  K3: {format(k3_val, '016X')}")

    start = time.perf_counter()
    subkeys1 = generate_subkeys(k1_val)
    subkeys2 = generate_subkeys(k2_val)
    subkeys3 = generate_subkeys(k3_val)
    elapsed_ms = (time.perf_counter() - start) * 1000

    if verbose:
        print(f"\n  Thời gian sinh 3 bộ subkeys: {elapsed_ms:.4f} ms")
        print(f"\n  {'Vòng':<6} {'K1 Subkey':<15} {'K2 Subkey':<15} {'K3 Subkey':<15}")
        print("  " + "-" * 52)
        for i in range(16):
            print(f"  {i+1:<6} {format(subkeys1[i], '012X'):<15} "
                  f"{format(subkeys2[i], '012X'):<15} "
                  f"{format(subkeys3[i], '012X'):<15}")

    return subkeys1, subkeys2, subkeys3, elapsed_ms


def time_key_generation(key_int: int, repeat: int = 1000) -> float:
    #Đo thời gian trung bình sinh 16 subkeys (lặp nhiều lần).
    #Trả về: thời gian trung bình (ms) cho mỗi lần sinh khóa.
    start = time.perf_counter()
    for _ in range(repeat):
        generate_subkeys(key_int)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed / repeat

