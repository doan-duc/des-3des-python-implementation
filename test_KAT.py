# -*- coding: utf-8 -*-
import os
import re
from member1_framework import DESKey, TripleDESKey, encrypt_data, decrypt_data, DESBlock
from member5_rounds import des_cipher

KAT_DIR = "KAT_TDES"  # NGƯỜI DÙNG ĐÃ ĐỔI TÊN

def parse_rsp_file(file_path):
    """
    Parser nâng cao cho file .rsp của NIST (hỗ trợ MMT và các định dạng khác).
    """
    test_cases = []
    current_section = None
    current_case = {}
    
    def sanitize_hex(val):
        # Loại bỏ các ký tự không phải hex như khoảng trắng, tab, xuống dòng, nháy
        return re.sub(r'[^0-9a-fA-F]', '', val).lower()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if line.startswith("["):
                current_section = line.strip("[]").upper()
                continue
            
            if "=" in line:
                parts = line.split("=", 1)
                key = parts[0].strip().upper()
                val = parts[1].strip()
                
                # COUNT là dấu hiệu bắt đầu một case mới
                if key == "COUNT":
                    if current_case:
                        current_case['section'] = current_section
                        test_cases.append(current_case)
                    current_case = {"COUNT": val}
                else:
                    # Các trường như KEY1, PLAINTEXT, CIPHERTEXT có thể là chuỗi Hex dài
                    if any(x in key for x in ["KEY", "PLAINTEXT", "CIPHERTEXT", "IV"]):
                        # NỐI TIẾP nếu field đã tồn tại (một số file NIST chia nhiều dòng)
                        current_case[key] = current_case.get(key, "") + sanitize_hex(val)
                    else:
                        current_case[key] = val
                    
        if current_case:
            current_case['section'] = current_section
            test_cases.append(current_case)
            
    return test_cases

def run_kat_test(file_name):
    file_path = os.path.join(KAT_DIR, file_name)
    cases = parse_rsp_file(file_path)
    
    # CHỈ TEST ECB VÀ CBC
    u_name = file_name.upper()
    if "CBC" in u_name:
        mode = "CBC"
    elif "ECB" in u_name:
        mode = "ECB"
    else:
        #print(f"    [SKIP] Chế độ không hỗ trợ (CFB/OFB): {file_name}")
        return 0, 0

    is_3des = True 
    
    print(f"\n>>> TEST FILE: {file_name}")
    print(f"    Mode: {mode}")
    
    passed = 0
    failed = 0
    
    for case in cases:
        section = case.get('section', 'ENCRYPT')
        is_encrypt = (section == 'ENCRYPT')
        
        # KEYING OPTIONS
        try:
            if 'KEY1' in case:
                k1 = DESKey.from_hex(case['KEY1'])
                k2 = DESKey.from_hex(case['KEY2'])
                k3 = DESKey.from_hex(case.get('KEY3', case['KEY1']))
                key = TripleDESKey(k1, k2, k3)
            elif 'KEYS' in case:
                k_val = DESKey.from_hex(case['KEYS'])
                key = TripleDESKey(k_val, k_val, k_val)
            else:
                continue
        except Exception:
            continue

        # IV
        iv_hex = case.get('IV1', case.get('IV', '0000000000000000'))
        iv_int = int(iv_hex, 16)
        
        if is_encrypt:
            pt_hex = case.get('PLAINTEXT')
            ct_exp = case.get('CIPHERTEXT1', case.get('CIPHERTEXT'))
            if not pt_hex or not ct_exp: continue
            
            try:
                data = bytes.fromhex(pt_hex)
                ct_res, _ = encrypt_data(data, key, des_cipher, use_3des=is_3des, 
                                       mode=mode, iv=iv_int, padding=False)
                
                if ct_res.hex().lower() == ct_exp.lower():
                    passed += 1
                else:
                    failed += 1
                    # print(f"    [FAIL] Count {case['COUNT']}")
            except Exception:
                failed += 1
        else:
            ct_hex = case.get('CIPHERTEXT1', case.get('CIPHERTEXT'))
            pt_exp = case.get('PLAINTEXT1', case.get('PLAINTEXT'))
            if not ct_hex or not pt_exp: continue
            
            try:
                data = bytes.fromhex(ct_hex)
                pt_res, _ = decrypt_data(data, key, des_cipher, use_3des=is_3des, 
                                       mode=mode, iv=iv_int, padding=False)
                
                if pt_res.hex().lower() == pt_exp.lower():
                    passed += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
                
    total = passed + failed
    if total > 0:
        print(f"    KẾT QUẢ: {passed}/{total} PASS")
    return passed, total

def main():
    if not os.path.exists(KAT_DIR):
        print(f"Lỗi: Không tìm thấy thư mục {KAT_DIR}")
        return

    files = os.listdir(KAT_DIR)
    
    overall_passed = 0
    overall_total = 0
    
    print("="*60)
    print("      HỆ THỐNG KIỂM THỬ TỰ ĐỘNG KAT (CHỈ ECB/CBC)")
    print("="*60)
    
    for f in files:
        if f.endswith(".rsp"):
            p, t = run_kat_test(f)
            overall_passed += p
            overall_total += t
            
    print("\n" + "="*60)
    print(f" TỔNG CỘNG: {overall_passed}/{overall_total} TEST CASES VƯỢT QUA")
    print("="*60)

if __name__ == "__main__":
    main()
