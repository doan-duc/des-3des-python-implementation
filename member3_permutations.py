
from typing import List, Tuple
from member4_sbox import E_TABLE  # type: ignore
#  BANG HOAN VI KHOI TAO IP 
# IP: 64-bit plaintext  sap xep lai cac bit theo thu tu co dinh
IP: List[int] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
# Sau IP: tach thanh L0 32-bit  va R0 32-bit 
# BANG HOAN VI KET THUC FP 
FP: List[int] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]
#  BANG HOAN VI P  32-bit -> 32-bit (sau S-box)
#  hoan vi 32-bit ket qua tu S-box truoc khi XOR voi nua trai L.
P_TABLE: List[int] = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

def permute(bits: int, table: List[int], input_size: int) -> int:
    """
    Ap dung bang hoan vi len chuoi bit bieu dien bang so nguyen.
        bits       : int       - so nguyen chua chuoi bit dau vao
        table      : List[int] - bang hoan vi 
        input_size : int       - tong so bit dau vao
    """
    result = 0
    output_size = len(table)
    for i in range(output_size):
        bit_pos = table[i]                       # Vi tri bit can lay (1-indexed)
        shift_in = input_size - bit_pos          # Dich phai de lay bit do
        bit_val = (bits >> shift_in) & 1         # Gia tri bit (0 hoac 1)
        shift_out = output_size - 1 - i          # Vi tri trong ket qua
        result |= (bit_val << shift_out)
    return result

#  HOAN VI KHOI TAO VA KET THUC

def initial_permutation(block_64: int) -> int:
    """
    Ap dung hoan vi IP len block 64-bit dau vao.
    Bien doi: block 64-bit goc -> block 64-bit sau IP
    Sau do tach thanh:
        L0 = 32 bit 
        R0 = 32 bit 
    """
    return permute(block_64, IP, input_size=64)


def final_permutation(block_64: int) -> int:
    """
    Ap dung  sau 16 vong. khoi phuc trat tu bit ban dau.
    Bien doi: ket hop R16 || L16 (64-bit) -> ciphertext 64-bit
    """
    return permute(block_64, FP, input_size=64)
#  HAM F
def feistel_f(R: int, subkey: int, sbox_fn: object) -> int:
    """
        R       : int    - nua phai 32-bit cua block hien tai
        subkey  : int    - subkey 48-bit cua vong hien tai
        sbox_fn : object - ham tra S-box 
    Tra ve: int - ket qua 32-bit cua ham F
    """
    #  Mo rong E  R 32-bit -> 48-bit
    R_expanded = permute(R, E_TABLE, input_size=32)
    #  XOR voi K
    xor_result = R_expanded ^ subkey
    #  Tra S-box  48-bit -> 32-bit 
    s_output: int = sbox_fn(xor_result)  
    #  Hoan vi P  32-bit -> 32-bit
    f_output = permute(s_output, P_TABLE, input_size=32)
    return f_output
#  VONG FEISTEL
def feistel_round(
    L: int,
    R: int,
    subkey: int,
    sbox_fn: object,
    round_num: int = 0,
    verbose: bool = False,
) -> Tuple[int, int]:
    """
    Thuc hien 1 vong  Feistel 
        L        : int    - nua trai 32-bit hien tai
        R        : int    - nua phai 32-bit hien tai
        subkey   : int    - subkey 48-bit cho vong nay
        sbox_fn  : object - ham tra S-box tu Thanh vien 4
        round_num: int    - so thu tu vong (de in debug)
        verbose  : bool   - in chi tiet tung buoc

    Tra ve: (L_new, R_new)  hai so nguyen 32-bit
    """
    if verbose:
        print(f"    Vong {round_num:>2}: L={format(L, '08X')}  R={format(R, '08X')}  "
              f"K={format(subkey, '012X')}")
    # Tinh ham F(R, subkey)
    f_result = feistel_f(R, subkey, sbox_fn)
    if verbose:
        R_exp = permute(R, E_TABLE, input_size=32)
        xor_val = R_exp ^ subkey
        print(f"           E(R)={format(R_exp, '012X')}  "
              f"XOR-K={format(xor_val, '012X')}  "
              f"F={format(f_result, '08X')}")
    # Cap nhat L va R theo  Feistel
    L_new = R                   
    R_new = L ^ f_result    #    XOR F(R, K)
    if verbose:
        print(f"           -> L_new={format(L_new, '08X')}  R_new={format(R_new, '08X')}")
    return L_new, R_new