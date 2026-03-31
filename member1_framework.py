
from __future__ import annotations
from typing import List, Tuple, Callable, Optional
import time


class DESBlock:  # biểu diễn dữ liệu 64 bit

    def __init__(self, value: int) -> None:
        # Đảm bảo giá trị không vượt quá 64-bit
        self.value: int = value & 0xFFFFFFFFFFFFFFFF

    def to_bytes(self) -> bytes: # chuyển 64 bit thành 8 bytes
        return self.value.to_bytes(8, byteorder='big')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DESBlock':    #tạo block từ 8 bytes
        if len(data) != 8:
            raise ValueError(f"DESBlock cần đúng 8 byte, nhận được {len(data)} byte")
        return cls(int.from_bytes(data, byteorder='big'))

    def to_bin_str(self) -> str:         #hiển thị block 64bit
        return format(self.value, '064b')

    def to_hex_str(self) -> str:         #hiển thị block 16hex
        return format(self.value, '016X')

    def __repr__(self) -> str:
        return f"DESBlock(hex={self.to_hex_str()})"


class DESKey:  #khóa des

    def __init__(self, value: int) -> None:
        self.value: int = value & 0xFFFFFFFFFFFFFFFF

    def to_bytes(self) -> bytes:  #chuyển thành 8bytes
        return self.value.to_bytes(8, byteorder='big')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DESKey':        #Tạo DESKey từ 8 bytes
        if len(data) != 8:
            raise ValueError(f"DESKey cần đúng 8 byte, nhận được {len(data)} byte")
        return cls(int.from_bytes(data, byteorder='big'))

    @classmethod
    def from_hex(cls, hex_str: str) -> 'DESKey':  #Tạo DESKey từ chuỗi hex 16 ký tự.
        clean = hex_str.replace(' ', '').replace('0x', '').replace('0X', '')
        if len(clean) != 16:
            raise ValueError(
                f"Khóa DES phải là 16 ký tự hex (64-bit), "
                f"nhận được {len(clean)} ký tự"
            )
        return cls(int(clean, 16))

    def to_hex_str(self) -> str:
        return format(self.value, '016X')

    def __repr__(self) -> str:
        return f"DESKey(hex={self.to_hex_str()})"


class TripleDESKey:  # khóa 3des gồm k1 k2 k3
    def __init__(
        self,
        k1: DESKey,
        k2: DESKey,
        k3: Optional[DESKey] = None
    ) -> None:
        self.k1: DESKey = k1
        self.k2: DESKey = k2
        self._k3: Optional[DESKey] = k3 # khóa 3 có thể có hoặc 0

    def get_k3(self) -> DESKey:
        k3_local: Optional[DESKey] = self._k3
        if k3_local is not None:
            return k3_local
        return self.k1  # nếu khóa 3 có thì thành Deskey o có thì thành k1

    def __repr__(self) -> str:
        mode = "3TDEA (3 khóa)" if self._k3 is not None else "2TDEA (2 khóa)"
        return (
            f"TripleDESKey({mode})\n"
            f"  K1={self.k1}\n"
            f"  K2={self.k2}\n"
            f"  K3={self.get_k3()}"
        )


#Bộ đệm pkc7

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes: # thêm bộ đệm bằng công thức pad_len = block_size - (len(data) % block_size)

    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes: # bỏ bộ đệm với byte cuối là số byte đã thêm
    
    if not data:  
        raise ValueError("Dữ liệu rỗng, không thể loại đệm")

    # Lấy giá trị byte cuối để biết độ dài đệm
    pad_len = int(data[-1])

    if pad_len == 0 or pad_len > 8:
        raise ValueError(f"Giá trị đệm không hợp lệ: {pad_len}")

    # Lấy phần đệm (pad_len byte cuối) để kiểm tra
    # Dùng bytearray + explicit index thay vì slice âm để tránh lỗi Pyre2
    data_len = len(data)
    tail_start = data_len - pad_len
    tail = bytes(bytearray(data[j] for j in range(tail_start, data_len)))
    expected_padding = bytes([pad_len] * pad_len)

    if tail != expected_padding:
        raise ValueError("Đệm PKCS#7 không hợp lệ: các byte đệm không khớp")

    # Trả về phần dữ liệu thực
    result_len = data_len - pad_len
    return bytes(bytearray(data[j] for j in range(result_len)))


def split_into_blocks(data: bytes) -> List[DESBlock]: #chia dữ liệu thành các desblocks chia hết cho 8
    
    if len(data) % 8 != 0:
        raise ValueError(
            f"Dữ liệu phải chia hết cho 8 byte, hiện tại: {len(data)} byte"
        )
    blocks: List[DESBlock] = []
    i = 0
    while i < len(data):
        # Lấy 8 byte tại vị trí i — dùng bytearray để Pyre2 chấp nhận
        chunk = bytes(bytearray(data[j] for j in range(i, i + 8)))
        blocks.append(DESBlock.from_bytes(chunk))
        i += 8
    return blocks


def blocks_to_bytes(blocks: List[DESBlock]) -> bytes:
    """Ghép danh sách DESBlock thành chuỗi byte liên tục."""
    result = b''
    for block in blocks:
        result += block.to_bytes()
    return result


DESCipherFn = Callable[..., DESBlock]


def triple_des_encrypt_block(      # luồng 3Des DED
    plaintext_block: DESBlock,
    triple_key: TripleDESKey,
    des_cipher_fn: DESCipherFn,
    verbose: bool = False,
) -> DESBlock:

    k1 = triple_key.k1
    k2 = triple_key.k2
    k3 = triple_key.get_k3()

    if verbose:
        print(f"    [3DES-ENC] Đầu vào   : {plaintext_block.to_hex_str()}")

    # Bước 1: E(K1, plaintext)
    step1: DESBlock = des_cipher_fn(plaintext_block, k1, encrypt=True)
    if verbose:
        print(f"    [3DES-ENC] Sau E(K1) : {step1.to_hex_str()}")

    # Bước 2: D(K2, step1)
    step2: DESBlock = des_cipher_fn(step1, k2, encrypt=False)
    if verbose:
        print(f"    [3DES-ENC] Sau D(K2) : {step2.to_hex_str()}")

    # Bước 3: E(K3, step2)
    step3: DESBlock = des_cipher_fn(step2, k3, encrypt=True)
    if verbose:
        print(f"    [3DES-ENC] Sau E(K3) : {step3.to_hex_str()}")

    return step3


def triple_des_decrypt_block(     #luồng 3des DED
    ciphertext_block: DESBlock,
    triple_key: TripleDESKey,
    des_cipher_fn: DESCipherFn,
    verbose: bool = False,
) -> DESBlock:
    
    k1 = triple_key.k1
    k2 = triple_key.k2
    k3 = triple_key.get_k3()

    if verbose:
        print(f"    [3DES-DEC] Đầu vào   : {ciphertext_block.to_hex_str()}")

    # Bước 1: D(K3, ciphertext)
    step1: DESBlock = des_cipher_fn(ciphertext_block, k3, encrypt=False)
    if verbose:
        print(f"    [3DES-DEC] Sau D(K3) : {step1.to_hex_str()}")

    # Bước 2: E(K2, step1)
    step2: DESBlock = des_cipher_fn(step1, k2, encrypt=True)
    if verbose:
        print(f"    [3DES-DEC] Sau E(K2) : {step2.to_hex_str()}")

    # Bước 3: D(K1, step2)
    step3: DESBlock = des_cipher_fn(step2, k1, encrypt=False)
    if verbose:
        print(f"    [3DES-DEC] Sau D(K1) : {step3.to_hex_str()}")

    return step3

# hàm tổng hợp mã hóa/ giải mã dữ liệu ECB
def encrypt_data(
    plaintext: bytes,
    key_or_keys: object,
    des_fn: DESCipherFn,
    use_3des: bool = False,
    verbose: bool = False,
    **kwargs: object,
) -> Tuple[bytes, float]:
    
    start_time = time.perf_counter()
    padding = kwargs.get('padding', True)
    mode = str(kwargs.get('mode', 'ECB')).upper()
    iv_obj = kwargs.get('iv', 0)
    
    # Lấy giá trị IV kiểu số nguyên
    if isinstance(iv_obj, DESBlock):
        iv_val = iv_obj.value
    else:
        iv_val = int(iv_obj) # type: ignore

    # Bước 1: Padding
    if padding:
        padded = pkcs7_pad(plaintext)
    else:
        if len(plaintext) % 8 != 0:
            raise ValueError("Dữ liệu không đệm phải chia hết cho 8 byte!")
        padded = plaintext

    if verbose:
        print(f"  Chế độ mã hóa: {mode}")
        print(f"  Dữ liệu gốc  : {len(plaintext)} byte")
        if padding:
            print(f"  Sau padding  : {len(padded)} byte ({len(padded) // 8} block)")

    # Bước 2: Chia blocks
    blocks = split_into_blocks(padded)

    # Bước 3: Mã hóa từng block
    encrypted_blocks: List[DESBlock] = []
    prev_cipher = iv_val # Dùng cho CBC

    for idx, block in enumerate(blocks):
        if verbose:
            print(f"\n  --- Block {idx + 1}/{len(blocks)} ---")
            print(f"  Plaintext    : {block.to_hex_str()}")

        # Xử lý input theo chế độ
        current_block_input = block
        if mode == 'CBC':
            # XOR với ciphertext của block trước đó (hoặc IV)
            xor_val = block.value ^ prev_cipher
            current_block_input = DESBlock(xor_val)
            if verbose:
                print(f"  CBC XOR Input: {current_block_input.to_hex_str()} (XOR với {format(prev_cipher, '016X')})")

        # Mã hóa khối hiện tại
        if use_3des:
            enc = triple_des_encrypt_block(
                current_block_input,
                key_or_keys,  # type: ignore[arg-type]
                des_fn,
                verbose,
            )
        else:
            enc = des_fn(current_block_input, key_or_keys, encrypt=True)

        if mode == 'CBC':
            prev_cipher = enc.value # Lưu lại ciphertext của block này

        if verbose:
            print(f"  Ciphertext   : {enc.to_hex_str()}")
        encrypted_blocks.append(enc)

    # Bước 4: Ghép lại
    ciphertext = blocks_to_bytes(encrypted_blocks)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return ciphertext, elapsed_ms


def decrypt_data(  # giải mã tổng hợp
    ciphertext: bytes,
    key_or_keys: object,
    des_fn: DESCipherFn,
    use_3des: bool = False,
    verbose: bool = False,
    **kwargs: object,
) -> Tuple[bytes, float]:
    
    start_time = time.perf_counter()
    mode = str(kwargs.get('mode', 'ECB')).upper()
    iv_obj = kwargs.get('iv', 0)
    
    if isinstance(iv_obj, DESBlock):
        iv_val = iv_obj.value
    else:
        iv_val = int(iv_obj) # type: ignore

    if len(ciphertext) % 8 != 0:
        raise ValueError(
            f"Dữ liệu mã hóa phải chia hết cho 8 byte, "
            f"hiện tại: {len(ciphertext)} byte"
        )

    # Bước 1: Chia blocks
    blocks = split_into_blocks(ciphertext)
    if verbose:
        print(f"  Chế độ giải mã: {mode}")
        print(f"  Dữ liệu mã hóa: {len(ciphertext)} byte ({len(blocks)} block)")

    # Bước 2: Giải mã từng block
    decrypted_blocks: List[DESBlock] = []
    prev_cipher = iv_val # Dùng cho CBC

    for idx, block in enumerate(blocks):
        if verbose:
            print(f"\n  --- Block {idx + 1}/{len(blocks)} ---")
            print(f"  Ciphertext   : {block.to_hex_str()}")

        # Giải mã khối hiện tại bằng thuật toán core
        if use_3des:
            dec_raw = triple_des_decrypt_block(
                block,
                key_or_keys,  # type: ignore[arg-type]
                des_fn,
                verbose,
            )
        else:
            dec_raw = des_fn(block, key_or_keys, encrypt=False)

        # Xử lý output theo chế độ
        if mode == 'CBC':
            # XOR bản thô sau giải mã với ciphertext của khối trước đó
            actual_plain_val = dec_raw.value ^ prev_cipher
            dec = DESBlock(actual_plain_val)
            if verbose:
                print(f"  CBC XOR Dec  : {dec.to_hex_str()} (XOR với {format(prev_cipher, '016X')})")
            
            # Lưu lại ciphertext block này để dùng cho block tiếp theo
            prev_cipher = block.value 
        else:
            dec = dec_raw

        if verbose:
            print(f"  Plaintext    : {dec.to_hex_str()}")
        decrypted_blocks.append(dec)

    # Bước 3: Ghép lại và loại đệm
    padding = kwargs.get('padding', True)
    padded_plain = blocks_to_bytes(decrypted_blocks)
    
    if padding:
        plaintext = pkcs7_unpad(padded_plain)
    else:
        plaintext = padded_plain

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return plaintext, elapsed_ms


def print_separator(char: str = "=", width: int = 60) -> None:
    """In đường kẻ phân cách."""
    print(char * width)

def display_block_info(label: str, block: DESBlock) -> None:
    """Hiển thị thông tin một DESBlock dạng hex + nhị phân."""
    bin_full = block.to_bin_str()
    bin_preview = "".join(list(bin_full)[k] for k in range(32))
    print(f"  {label:<22}: {block.to_hex_str()}  (bin: {bin_preview}...)")
    #commit
