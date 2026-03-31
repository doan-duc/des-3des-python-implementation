# -*- coding: utf-8 -*-
# =============================================================================
# THÀNH VIÊN 5: TÍCH HỢP VÒNG LẶP DES VÀ KIỂM THỬ
# =============================================================================

from typing import List, Tuple, cast
import time
import os

# Import các module (thêm type ignore để IDE không báo lỗi import local)
from member1_framework import (  # type: ignore
    DESBlock,
    DESKey,
    TripleDESKey,
    encrypt_data,
    decrypt_data,
)
from member2_keyschedule import (  # type: ignore
    generate_subkeys,
    generate_all_3des_subkeys,
)
from member3_permutations import (  # type: ignore
    initial_permutation,
    final_permutation,
    feistel_round,
)
from member4_sbox import sbox_substitute  # type: ignore


def des_16_rounds(
    block_64: int,
    subkeys: List[int],
    encrypt: bool = True,
    verbose: bool = False,
) -> int:
    """Thực hiện toàn bộ 16 vòng DES trên một block 64-bit."""
    # Bước 1: Hoán vị khởi tạo (IP) - xáo trộn 64 bit ban đầu
    permuted = initial_permutation(block_64)
    
    # Bước 2: Chia khối 64-bit thành 2 nửa: L (nửa trái 32-bit) và R (nửa phải 32-bit)
    L = (permuted >> 32) & 0xFFFFFFFF
    R = permuted & 0xFFFFFFFF

    # Bước 3: Xác định thứ tự dùng khóa con (Mã hóa: K1->K16, Giải mã: K16->K1)
    active_subkeys = subkeys if encrypt else list(reversed(subkeys))

    # Bước 4: Lặp 16 vòng Feistel biến đổi dữ liệu
    for rnd in range(16):
        subkey = active_subkeys[rnd]
        # Mỗi vòng thực hiện XOR, S-box substitution và hoán vị P qua hàm feistel_round
        L, R = feistel_round(L, R, subkey, sbox_substitute, round_num=rnd + 1)

    # Bước 5: Kết thúc 16 vòng - Ghép THEO THỨ TỰ R16 || L16 (không swap ở vòng cuối)
    R_int: int = int(R)  # ép kiểu số nguyên cho nửa phải
    L_int: int = int(L)  # ép kiểu số nguyên cho nửa trái
    pre_fp = (R_int << 32) | L_int # Ghép R vào 32 bit cao, L vào 32 bit thấp
    
    # Bước 6: Hoán vị kết thúc (FP) - nghịch đảo của IP để ra kết quả cuối cùng
    return final_permutation(pre_fp)


def des_cipher(
    block: DESBlock,
    key: DESKey,
    encrypt: bool = True,
    verbose: bool = False,
) -> DESBlock:
    """Interface chính: mã hóa/giải mã 1 block với 1 khóa."""
    # Sinh 16 khóa con (mỗi khóa 48-bit) từ khóa gốc 64-bit
    subkeys = generate_subkeys(key.value)
    
    # Thực hiện 16 vòng lặp xử lý khối dữ liệu
    output_int = des_16_rounds(block.value, subkeys, encrypt=encrypt, verbose=verbose)
    
    # Trả về kết quả dưới dạng đối tượng DESBlock
    return DESBlock(output_int)

def encrypt_file(input_path: str, output_path: str, key_or_keys: object, use_3des: bool = False, verbose: bool = False) -> dict:
    with open(input_path, 'rb') as f:
        data = f.read()
    ct, t = encrypt_data(data, key_or_keys, des_cipher, use_3des=use_3des, verbose=verbose)
    with open(output_path, 'wb') as f:
        f.write(ct)
    return {"original_size": len(data), "encrypted_size": len(ct), "num_blocks": len(ct)//8, "t_enc_ms": t, "t_keygen_ms": 0.0}  # type: ignore


def decrypt_file(input_path: str, output_path: str, key_or_keys: object, use_3des: bool = False, verbose: bool = False) -> dict:
    with open(input_path, 'rb') as f:
        data = f.read()
    pt, t = decrypt_data(data, key_or_keys, des_cipher, use_3des=use_3des, verbose=verbose)
    with open(output_path, 'wb') as f:
        f.write(pt)
    return {"encrypted_size": len(data), "decrypted_size": len(pt), "t_dec_ms": t}  # type: ignore

