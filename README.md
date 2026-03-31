# Mô Phỏng Hệ Thống Mã Hóa DES và 3DES

Đây là dự án mô phỏng hoạt động mã hóa và giải mã chuẩn DES (Data Encryption Standard) cùng với 3DES (Triple DES). Dự án được triển khai bằng Python dưới dạng giao diện dòng lệnh (CLI).

## 1. Phân Công Nhiệm Vụ

Dưới đây là bảng phân công công việc chi tiết của nhóm bao gồm 5 thành viên để phối hợp tạo nên một hệ thống hoàn chỉnh.

| Họ và Tên | MSSV | Phân Công Công Việc |
| :--- | :--- | :--- |
| Đoàn Sinh Đức | 20234000 | Chịu trách nhiệm tổng hợp code kết nối các module lại với nhau, viết chương trình chính `main.py` (cung cấp GUI chuẩn CLI cho user), đồng thời viết file `member5_rounds.py` thực hiện logic lõi của chu trình ghép nối (16 vòng mã hóa chính với hàm Feistel). |
| Nguyễn Minh Đức | 20234001 | Xây dựng bộ khung hệ thống (`member1_framework.py`). Phụ trách xử lý Padding (chuẩn PKCS#7), chia cắt dữ liệu thành từng khối (blocks 64-bit), ghép chuỗi, và viết hàm bao đóng để điều phối quy trình chạy mã hóa/giải mã nhiều lớp cho 3DES (EDE/DED) và các mode (ECB, CBC). |
| Nguyễn Đoàn Thùy Dương | 20234004 | Triển khai cơ chế sinh khóa con (Key Schedule) trong file `member2_keyschedule.py`. Chịu trách nhiệm thực hiện phép biến đổi PC-1, PC-2, phân chia khóa và dịch trái vòng tròn (Left Shifts) để tạo ra 16 khóa 48-bit từ khóa gốc 64-bit. |
| Vũ Trí Dũng | 20234003 | Chịu trách nhiệm cấu trúc tất cả các bảng hoán vị cố định trong file `member3_permutations.py`. Thiếp lập logic cho hoán vị khởi tạo (IP), hoán vị kết thúc (FP), hoán vị mở rộng (E-Box) và hoán vị P-Box. |
| Hoàng Mạnh Dũng | 20234002 | Phát triển logic thay thế dữ liệu phi tuyến (Substitution) ở `member4_sbox.py`. Xác định 8 bảng S-Box trong chuẩn DES và viết hàm chuyển đổi tính toán rút gọn 6-bit thành 4-bit của mỗi hộp S. |


---

## 2. Mô Tả Dự Án

Dự án này là một **Hệ thống Mô phỏng Thuật toán Mã hóa Cổ điển DES và 3DES**, được viết thuần bằng ngôn ngữ Python với mục tiêu phục vụ việc học tập, nghiên cứu và làm bài tập lớn bộ môn An Toàn Thông Tin. 

**Các thành phần kỹ thuật nổi bật:**
- **Thuật toán hỗ trợ:** DES (viết tắt) và Triple-DES (kết hợp 3 khóa K1, K2, K3) hoạt động hoàn chỉnh cho việc mã hóa (Encrypt) và giải mã (Decrypt).
- **Chế độ hoạt động (Operating Modes):** Hỗ trợ đầy đủ khối thông thường ECB (Electronic Codebook) và vòng lặp khối tự động CBC (Cipher Block Chaining).
- **Độ chính xác chuẩn NIST:** Khối mã hóa lõi đã được kiểm thử chạy qua bộ **Known Answer Tests (KAT)** của chuẩn NIST, đảm bảo output của trình giả lập khớp hoàn hảo từng bit so với các tài liệu mã hóa quốc tế.
- **Tính module:** Code được chia cắt rõ ràng theo đúng 5 bộ phận (Framework, Rounds, Keyschedule, Permutations, S-Boxes) giúp cực kì thuận tiện cho việc debug và đọc cấu trúc code chuẩn DES sách giáo khoa.

### Hướng Dẫn Chạy Dự Án

Dự án hỗ trợ 2 phương pháp khởi chạy ứng dụng:

**Cách 1: Chạy bằng mã nguồn Python (Dành cho Developer)**
1. Mở Terminal và clone kho lưu trữ về máy:
   ```bash
   git clone https://github.com/doan-duc/des-3des-python-implementation.git
   cd des-3des-python-implementation
   ```
2. Cài đặt Python kích hoạt trên máy tính (phiên bản >3.8).
3. Thực thi lệnh: 
   ```bash
   python main.py
   ```
4. Giao diện chương trình sẽ hiển thị trực tiếp lên Terminal.

**Cách 2: Mở ứng dụng đã dịch sẵn (.exe) (Dành cho User)**
1. Các thành viên đã đóng gói toàn bộ chương trình lại thành 1 file chạy độc lập. 
2. Truy cập vào thư mục con `dist/` nằm trong dự án.
3. Click nháy đúp chuột vào file executable có tên: `DES_Simulator_2026.exe`.
4. Cửa sổ Command Prompt của ứng dụng sẽ được mở lên mà không cần phải cài Python.

*(Tip: Nếu bạn thay đổi source code và muốn tự Build lại bản `exe` mới, hãy chạy script: `pyinstaller --noconfirm DES_Simulator_2026.spec` ở thư mục gốc).*

---

## 3. Cấu Trúc Thư Mục Dự Án

Dàn mã nguồn và dữ liệu kiểm thử được tổ chức rõ ràng theo chuẩn module hóa như sau:

```text
BTL_ATTT/
│
├── dist/                          # Chứa phần mềm đóng gói hoàn chỉnh chạy độc lập
│   └── DES_Simulator_2026.exe     # File thực thi ứng dụng trực tiếp (.exe)
│
├── KAT_TDES/                      # Thư viện Known Answer Tests (NIST) cho ECB/CBC
├── tdesmmt/                       # Thư viện Multi-block Message Tests (NIST)
│
├── main.py                        # Chương trình gốc - chứa giao diện CLI Menu Console
├── member1_framework.py           # Module: Quản trị framework (Padding, chia khối, mode)
├── member2_keyschedule.py         # Module: Sinh khóa con (Key Schedule - PC1, PC2, Shift)
├── member3_permutations.py        # Module: Hoán vị tĩnh (IP, FP, E-Box, P-Box)
├── member4_sbox.py                # Module: Hộp thay thế phi tuyến (S-Box)
├── member5_rounds.py              # Module: Lõi dịch bit (Mạng Feistel, 16 Rounds)
├── test_KAT.py                    # Script: Tự động tải file trong KAT_TDES để chạy test
│
├── .gitignore                     # Tệp cấu hình GitHub
├── DES_Simulator_2026.spec        # Tệp cấu hình để PyInstaller build ra file .exe
├── LICENSE                        # Giấy phép mã nguồn mở (MIT License)
└── README.md                      # Tài liệu mô tả dự án (bạn đang đọc)
```

---

## 4. Bản Demo Dự Án (Chạy test ví dụ KAT_TDES)

Để minh chứng cho việc hệ thống hoạt động chính xác theo chuẩn Hoa Kỳ (NIST), sau đây là bản chạy demo trực tiếp trên giao diện dòng lệnh của trình giả lập (`main.py`). Bản chạy dưới đây thực hiện mã hóa 1 Test Case chuẩn trong file `C:\BTL_ATTT\KAT_TDES\TECBvartext.rsp` (Test Case số 0).

**Thông tin Test Case (đầu vào):**
- **Mode:** 3DES - ECB
- **Khóa (Key):** `0101010101010101` (dùng khóa bộ 3 giống nhau K1 = K2 = K3)
- **Plaintext:** `8000000000000000`

**Quá trình khởi chạy và tương tác trên Terminal:**
```text
C:\BTL_ATTT> python main.py

╔════════════════════════════════════════════════╗
║          HỆ THỐNG MÔ PHỎNG DES / 3DES          ║
╚════════════════════════════════════════════════╝
  1. Mã hóa văn bản (Text -> Hex)
  2. Giải mã văn bản (Hex -> Text)
  0. Thoát

Lựa chọn công việc: 1

>>> CHỨC NĂNG: MÃ HÓA VĂN BẢN
  Sử dụng 3DES? (y/n): y

--- NHẬP 3 KHÓA CHO 3DES ---
  Nhập khóa K1 (16 ký tự hex):
  > 0101010101010101
  Nhập khóa K2 (16 ký tự hex):
  > 0101010101010101
  Nhập khóa K3 (16 ký tự hex):
  > 0101010101010101

  Chọn chế độ mã hóa (Block Mode):
  1. ECB (Electronic Codebook)
  2. CBC (Cipher Block Chaining)

Lựa chọn: 1

  Bạn muốn nhập gì?
  1. Văn bản (Text/String)
  2. Chuỗi Hex

Lựa chọn: 2
  Nhập chuỗi Plaintext (Hex): 8000000000000000

--- KẾT QUẢ MÃ HÓA ---
  Chế độ        : ECB
  Ciphertext (H): 95F8A5E5DD31D900
  Độ dài         : 8 bytes (1 blocks)
  Thời gian xử lý : 0.0012 ms
  Status: [Smart Padding] Dữ liệu chuẩn 64-bit -> KHÔNG đệm.

Nhấn Enter để quay lại Menu...
```

---

## 5. Tổng Kết

Trải qua quá trình làm bài và phối hợp cùng nhau, các thành viên trong nhóm đã hoàn thiện trọn vẹn dự án với mức độ tin cậy và hoàn thành rất tốt:
1. **Phối hợp nhóm hiệu quả:** Công đoạn phát triển đã được chia nhỏ và độc lập theo từng component phần cứng của luồng dữ liệu (5 module riêng biệt do 5 người viết). Việc lắp ráp dưới bàn tay của Mem 5 cho thấy cấu trúc hướng đối tượng và liên kết file trong Python hoạt động vững chắc.
2. **Giá trị kỹ thuật đạt được:** Không chỉ là một ứng dụng giao diện đơn thuần, dự án mã nguồn thỏa mãn mọi vector test (KAT) của chuẩn NIST một cách toàn vẹn qua hai file kiểm thử ECB và CBC, minh chứng cho sự tự cài đặt thuật toán không có điểm mù hay lỗi dịch bit nào.
3. **Tính ứng dụng cao:** Hệ thống CLI mượt mà được trang bị đủ tính năng đệm PKCS#7 để mã hóa/giải mã những đoạn văn bản thô tuỳ ý của người dùng, biến đây trở thành một tool hoàn chỉnh phục vụ thực tế ngoài đời thực.

*Cảm ơn đã theo dõi và sử dụng bộ mã nguồn này!*
