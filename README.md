
# **Thư viện Mật mã BMC (BMC Cryptographic Library)**

[](https://opensource.org/licenses/MIT)

Một thư viện C hiệu năng cao, cung cấp các chức năng mã hóa và băm tiêu chuẩn, được thiết kế để dễ dàng tích hợp vào các dự án khác, đặc biệt là Python. Toàn bộ thư viện được xây dựng từ đầu, tuân thủ các chuẩn NIST và cung cấp một lớp API Python tiện lợi thông qua `ctypes`.

## **Tính năng**

  * **Mã hóa AES:**
      * **Kích thước khóa:** 128, 192, và 256-bit.
      * [cite\_start]**Chế độ hoạt động:** CBC, ECB, và CTR[cite: 1, 2, 3, 4, 5].
      * Tự động xử lý đệm (padding) PKCS\#7 cho các chế độ CBC và ECB.
  * **Hàm băm (Hashing):**
      * [cite\_start]**SHA-2:** Triển khai SHA-256[cite: 6].
      * [cite\_start]**SHA-3:** Hỗ trợ SHA3-256, SHA3-384, và SHA3-512[cite: 6].
  * **Hiệu năng cao:** Toàn bộ logic mật mã được xử lý bằng mã C gốc đã được tối ưu.
  * [cite\_start]**Dễ sử dụng:** Cung cấp một lớp Python (`BCrypto`) đơn giản để che giấu sự phức tạp của việc gọi hàm C. [cite: 7]


## **Sử dụng**

Đặt file `libbmc_crypto.so` vừa được tạo vào cùng thư mục với script Python của bạn.

## **Hướng dẫn sử dụng (API Python)**

[cite\_start]Cách tốt nhất để sử dụng thư viện là thông qua lớp `BCrypto` được cung cấp. [cite: 7]

### **1. [cite\_start]Khởi tạo** [cite: 8]

```python
import ctypes
import os
from typing import Optional

# Đường dẫn đến thư viện đã biên dịch
LIB_PATH = './libbmc_crypto.so'

# Khởi tạo đối tượng
crypto = BCrypto(LIB_PATH)
```

### **2. Các phương thức chính**

#### `aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes | [cite_start]None` [cite: 8, 9]

Mã hóa dữ liệu bằng AES-128-CBC.

  * **Tham số:**
      * [cite\_start]`plaintext` (`bytes`): Dữ liệu gốc cần mã hóa. [cite: 9]
      * [cite\_start]`key` (`bytes`): Khóa mã hóa, bắt buộc phải dài 16 bytes cho AES-128[cite: 10].
      * [cite\_start]`iv` (`bytes`): Initialization Vector, bắt buộc phải dài 16 bytes[cite: 10].
  * **Trả về:**
      * [cite\_start]Một đối tượng `bytes` chứa dữ liệu đã mã hóa[cite: 11].
      * [cite\_start]`None` nếu có lỗi xảy ra[cite: 11].

#### `aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | [cite_start]None` [cite: 12]

Giải mã dữ liệu bằng AES-128-CBC.

  * **Tham số:**
      * [cite\_start]`ciphertext` (`bytes`): Dữ liệu đã mã hóa[cite: 12].
      * [cite\_start]`key` (`bytes`): Khóa giải mã, phải giống hệt khóa mã hóa và dài 16 bytes[cite: 13].
      * [cite\_start]`iv` (`bytes`): Initialization Vector, phải giống hệt IV đã dùng để mã hóa và dài 16 bytes[cite: 14].
  * **Trả về:**
      * [cite\_start]Một đối tượng `bytes` chứa dữ liệu gốc đã được giải mã[cite: 15].
      * [cite\_start]`None` nếu có lỗi (ví dụ: sai khóa, dữ liệu hỏng, hoặc lỗi padding)[cite: 16].

#### [cite\_start]`sha256(data: bytes) -> bytes` [cite: 17]

Băm dữ liệu bằng thuật toán SHA-256.

-----

### **Ví dụ hoàn chỉnh**

Dưới đây là một script Python đầy đủ để bạn có thể chạy thử ngay.

```python
import ctypes
import os
from typing import Optional

# Tên file thư viện .so
LIB_PATH = './libbmc_crypto.so'

class BCrypto:
    """
    Lớp Python wrapper để làm việc với thư viện C đa năng.
    """
    def __init__(self, library_path: str):
        if not os.path.exists(library_path):
            raise FileNotFoundError(f"Thư viện không được tìm thấy tại: {library_path}")
        
        self.lib = ctypes.CDLL(library_path)
        [cite_start]self._configure_functions() [cite: 18]
        [cite_start]print("Thư viện bmc_crypto đã được nạp thành công.") [cite: 18]

    def _configure_functions(self):
        [cite_start]"""Cấu hình chữ ký các hàm C dựa trên bmc_crypto.h""" [cite: 18]
        
        # --- AES Functions ---
        self.lib.bmc_aes_get_padded_size.argtypes = [ctypes.c_size_t]
        self.lib.bmc_aes_get_padded_size.restype = ctypes.c_size_t
        
        self.lib.bmc_aes128_cbc_encrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, 
            ctypes.c_void_p, ctypes.c_void_p
        [cite_start]] [cite: 19]
        [cite_start]self.lib.bmc_aes128_cbc_encrypt.restype = ctypes.c_int [cite: 19]

        self.lib.bmc_aes128_cbc_decrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t)
        [cite_start]] [cite: 19, 20]
        [cite_start]self.lib.bmc_aes128_cbc_decrypt.restype = ctypes.c_int [cite: 20]

        # --- SHA-256 Function ---
        [cite_start]self.lib.bmc_sha256.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p] [cite: 20]
        [cite_start]self.lib.bmc_sha256.restype = None [cite: 20]


    def aes_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Hàm mã hóa AES-128-CBC tiện lợi."""
        if len(key) != 16 or len(iv) != 16:
            [cite_start]print("Lỗi: Key và IV phải dài đúng 16 bytes.") [cite: 21]
            return None

        encrypted_size = self.lib.bmc_aes_get_padded_size(len(plaintext))
        encrypted_buf = ctypes.create_string_buffer(encrypted_size)
        
        result = self.lib.bmc_aes128_cbc_encrypt(
            plaintext, len(plaintext), key, iv, encrypted_buf
        )
        if result != 0: return None
        [cite_start]return encrypted_buf.raw [cite: 22]

    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Hàm giải mã AES-128-CBC tiện lợi."""
        if len(key) != 16 or len(iv) != 16:
            print("Lỗi: Key và IV phải dài đúng 16 bytes.")
            return None

        decrypted_buf = ctypes.create_string_buffer(len(ciphertext))
        [cite_start]actual_len = ctypes.c_size_t(0) [cite: 23]
        
        result = self.lib.bmc_aes128_cbc_decrypt(
            ciphertext, len(ciphertext), key, iv,
            decrypted_buf, ctypes.byref(actual_len)
        )
        if result != 0: return None
        return decrypted_buf.raw[:actual_len.value]

    def sha256(self, data: bytes) -> bytes:
        """Hàm băm SHA-256 tiện lợi."""
        [cite_start]hash_buf = ctypes.create_string_buffer(32) [cite: 24]
        self.lib.bmc_sha256(data, len(data), hash_buf)
        [cite_start]return hash_buf.raw [cite: 24]

# --- Kịch bản Test ---
if __name__ == "__main__":
    try:
        crypto = BCrypto(LIB_PATH)
        
        # --- Test AES ---
        print("\n--- TESTING AES-128-CBC ---")
        plaintext_aes = b"Testing the final modular library in Python!"
        [cite_start]key_aes = b'a-16-byte-secret' [cite: 25]
        [cite_start]iv_aes  = b'a-16-byte-vector' [cite: 25]

        encrypted = crypto.aes_encrypt(plaintext_aes, key_aes, iv_aes)
        if encrypted:
            print(f"AES Encrypted (hex): {encrypted.hex()}")
            decrypted = crypto.aes_decrypt(encrypted, key_aes, iv_aes)
            if decrypted:
                print(f"AES Decrypted: {decrypted.decode()}")
                [cite_start]assert plaintext_aes == decrypted [cite: 26]
                [cite_start]print("✅ AES Test PASSED") [cite: 26]
        
        # --- Test SHA-256 ---
        print("\n--- TESTING SHA-256 ---")
        input_sha = b"abc"
        expected_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        
        [cite_start]actual_hash = crypto.sha256(input_sha) [cite: 27]
        print(f"SHA-256 Input: '{input_sha.decode()}'")
        print(f"Actual Hash:   {actual_hash.hex()}")
        
        assert expected_hash == actual_hash.hex()
        print("✅ SHA-256 Test PASSED")

    except Exception as e:
        print(f"\n❌ Đã có lỗi xảy ra: {e}")
```

### **Lưu ý**

  * **Độ dài Key/IV:** Các hàm tiện lợi trong ví dụ (`aes_encrypt`, `aes_decrypt`) được viết cho AES-128. Bạn có thể dễ dàng tạo thêm các hàm mới (`aes_encrypt_256`,...) để gọi các phiên bản 192/256-bit từ thư viện C.
  * **An toàn luồng (Thread Safety):** Thư viện này không an toàn để sử dụng trên nhiều luồng nếu bạn dùng chung một đối tượng `BCrypto` mà không có cơ chế khóa (locking).

## **Giấy phép**

Dự án này được cấp phép theo Giấy phép MIT.
