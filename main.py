# -*- coding: utf-8 -*-
# FILE MAIN.PY — GIAO DIỆN TỔNG HỢP DES/3DES (ĐÃ TÁCH MÃ HÓA/GIẢI MÃ)
import os
import sys

from member1_framework import (  # type: ignore
    DESBlock, DESKey, TripleDESKey, encrypt_data, decrypt_data, print_separator,
)
from member5_rounds import (  # type: ignore
    des_cipher,
)

BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def enable_ansi_windows() -> None:
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

def cprint(text: str, color: str = "") -> None:
    print(f"{color}{text}{RESET}")

def get_choice(prompt: str, valid: list) -> str:
    while True:
        choice = input(f"\n{BOLD}{prompt}{RESET}").strip()
        if choice in valid: return choice
        cprint(f"  ✗ Lựa chọn không hợp lệ! {valid}", RED)
    return ""

def input_key_prompt(use_3des: bool) -> object:
    if use_3des:
        cprint("\n--- NHẬP 3 KHÓA CHO 3DES ---", BOLD)
        k1 = input_des_key("K1")
        k2 = input_des_key("K2")
        k3 = input_des_key("K3")
        return TripleDESKey(k1, k2, k3)
    else:
        return input_des_key("DES")

def input_des_key(label: str = "DES") -> DESKey:
    while True:
        cprint(f"  Nhập khóa {label} (16 ký tự hex):", BOLD)
        hex_str = input("  > ").strip().upper() or "133457799BBCDFF1"
        if len(hex_str) != 16:
            cprint("  ✗ Khóa phải đủ 16 ký tự hex!", RED)
            continue
        try:
            return DESKey.from_hex(hex_str)
        except:
            cprint("  ✗ Định dạng Hex không hợp lệ!", RED)

def get_mode_choice() -> str:
    print("\n  Chọn chế độ mã hóa (Block Mode):")
    print("  1. ECB (Electronic Codebook)")
    print("  2. CBC (Cipher Block Chaining)")
    choice = get_choice("Lựa chọn: ", ["1", "2"])
    return "ECB" if choice == "1" else "CBC"

def get_iv_input() -> int:
    while True:
        cprint("\n  Nhập Vector khởi tạo IV (16 ký tự hex):", BOLD)
        hex_str = input("  > ").strip().upper() or "0000000000000000"
        if len(hex_str) != 16:
            cprint("  ✗ IV phải đủ 16 ký tự hex!", RED)
            continue
        try:
            return int(hex_str, 16)
        except ValueError:
            cprint("  ✗ Định dạng IV Hex không hợp lệ!", RED)

def feature_text_encrypt() -> None:
    cprint("\n>>> CHỨC NĂNG: MÃ HÓA VĂN BẢN", BOLD + CYAN)
    use_3des = input("  Sử dụng 3DES? (y/n): ").lower() == 'y'
    key = input_key_prompt(use_3des)
    
    # Chọn Mode
    mode = get_mode_choice()
    iv = 0
    if mode == "CBC":
        iv = get_iv_input()
        
    print("\n  Bạn muốn nhập gì?")
    print("  1. Văn bản (Text/String)")
    print("  2. Chuỗi Hex")
    choice = get_choice("Lựa chọn: ", ["1", "2"])
    
    if choice == "2":
        hex_input = input("  Nhập chuỗi Plaintext (Hex): ").strip().replace(" ", "")
        try:
            data = bytes.fromhex(hex_input)
        except ValueError:
            cprint("  ✗ Chuỗi Hex không hợp lệ!", RED)
            return
    else:
        text = input("  Nhập văn bản cần mã hóa: ")
        data = text.encode('utf-8')
    
    # Logic Smart Padding:
    is_multiple = (len(data) % 8 == 0) and (len(data) > 0)
    use_padding = not is_multiple
    
    ct, t = encrypt_data(
        data, key, des_cipher, 
        use_3des=use_3des, 
        padding=use_padding, 
        mode=mode, 
        iv=iv
    )
    
    cprint("\n--- KẾT QUẢ MÃ HÓA ---", GREEN)
    print(f"  Chế độ        : {mode}")
    if mode == "CBC":
        print(f"  Vector IV     : {format(iv, '016X')}")
    print(f"  Ciphertext (H): {ct.hex().upper()}")
    print(f"  Độ dài         : {len(ct)} bytes ({len(ct)//8} blocks)")
    print(f"  Thời gian xử lý : {t:.4f} ms")
    
    if is_multiple:
        cprint("  Status: [Smart Padding] Dữ liệu chuẩn 64-bit -> KHÔNG đệm.", YELLOW)
    else:
        cprint("  Status: [Smart Padding] Dữ liệu lẻ -> Đã đệm PKCS#7.", YELLOW)

def feature_text_decrypt() -> None:
    cprint("\n>>> CHỨC NĂNG: GIẢI MÃ VĂN BẢN", BOLD + YELLOW)
    use_3des = input("  Sử dụng 3DES? (y/n): ").lower() == 'y'
    key = input_key_prompt(use_3des)
    
    # Chọn Mode
    mode = get_mode_choice()
    iv = 0
    if mode == "CBC":
        iv = get_iv_input()
        
    hex_input = input("\n  Nhập chuỗi Ciphertext (Hex): ").strip().replace(" ", "")
    
    try:
        data = bytes.fromhex(hex_input)
        
        # Logic giải mã: ưu tiên padding trước, nếu fail thì giải raw.
        try:
            pt_bytes, t = decrypt_data(
                data, key, des_cipher, 
                use_3des=use_3des, 
                padding=True, 
                mode=mode, 
                iv=iv
            )
            mode_msg = f"Giải mã {mode} với PKCS#7 Padding"
        except:
            pt_bytes, t = decrypt_data(
                data, key, des_cipher, 
                use_3des=use_3des, 
                padding=False, 
                mode=mode, 
                iv=iv
            )
            mode_msg = f"Giải mã {mode} KHÔNG Padding (Raw)"

        cprint("\n--- KẾT QUẢ GIẢI MÃ ---", GREEN)
        print(f"  Chế độ xử lý   : {mode_msg}")
        if mode == "CBC":
            print(f"  Vector IV      : {format(iv, '016X')}")
        print(f"  Plaintext (Hex): {pt_bytes.hex().upper()}")
        try:
            print(f"  Plaintext (Text): {pt_bytes.decode('utf-8')}")
        except:
            print(f"  Plaintext (Text): [Không thể giải mã UTF-8]")
        print(f"  Thời gian xử lý: {t:.4f} ms")
    except Exception as e:
        cprint(f"  ✗ Lỗi giải mã: {str(e)}", RED)

def main() -> None:
    enable_ansi_windows()
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        cprint("╔════════════════════════════════════════════════╗", CYAN)
        cprint("║          HỆ THỐNG MÔ PHỎNG DES / 3DES          ║", CYAN)
        cprint("╚════════════════════════════════════════════════╝", CYAN)
        print("  1. Mã hóa văn bản (Text -> Hex)")
        print("  2. Giải mã văn bản (Hex -> Text)")
        print("  0. Thoát")
        
        choice = get_choice("Lựa chọn công việc: ", ["0", "1", "2"])
        
        if choice == "0": break
        elif choice == "1": feature_text_encrypt()
        elif choice == "2": feature_text_decrypt()
        
        input(f"\n{BOLD}Nhấn Enter để quay lại Menu...{RESET}")

if __name__ == "__main__":
    main()
