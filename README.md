
# **Thư viện Mật mã BMC (BMC Cryptographic Library)**

[](https://opensource.org/licenses/MIT)

Một thư viện C hiệu năng cao, cung cấp các chức năng mã hóa và băm tiêu chuẩn, được thiết kế để dễ dàng tích hợp vào các dự án khác, đặc biệt là Python. Toàn bộ thư viện được xây dựng từ đầu, tuân thủ các chuẩn NIST và cung cấp một lớp API Python tiện lợi thông qua `ctypes`.

## **Tính năng**

  * **Mã hóa AES:**
      * **Kích thước khóa:** 128, 192, và 256-bit.
      * **Chế độ hoạt động:** CBC, ECB, và CTR.
      * Tự động xử lý đệm (padding) PKCS\#7 cho các chế độ CBC và ECB.
  * **Hàm băm (Hashing):**
      * **SHA-2:** Triển khai SHA-256.
      * **SHA-3:** Hỗ trợ SHA3-256, SHA3-384, và SHA3-512.
  * **Hiệu năng cao:** Toàn bộ logic mật mã được xử lý bằng mã C gốc đã được tối ưu.
  * **Dễ sử dụng:** Cung cấp một lớp Python (`BCrypto`) đơn giản để che giấu sự phức tạp của việc gọi hàm C. 


## **Sử dụng**

Đặt file `libbmc_cryptographic.so` vừa được tạo vào cùng thư mục với script Python của bạn.

## **Hướng dẫn sử dụng (API Python)**

Cách tốt nhất để sử dụng thư viện là thông qua lớp `BCrypto` được cung cấp. 

### **1. Khởi tạo** 

```python
import ctypes
import os
from typing import Optional

# Đường dẫn đến thư viện đã biên dịch
LIB_PATH = './libbmc_cryptographic.so'

# Khởi tạo đối tượng
crypto = BCrypto(LIB_PATH)
```

### **2. Các phương thức chính**

#### `aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes | None`

Mã hóa dữ liệu bằng AES-128-CBC.

  * **Tham số:**
      * `plaintext` (`bytes`): Dữ liệu gốc cần mã hóa. 
      * `key` (`bytes`): Khóa mã hóa, bắt buộc phải dài 16 bytes cho AES-128.
      * `iv` (`bytes`): Initialization Vector, bắt buộc phải dài 16 bytes.
  * **Trả về:**
      * Một đối tượng `bytes` chứa dữ liệu đã mã hóa.
      * `None` nếu có lỗi xảy ra.

#### `aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None` 

Giải mã dữ liệu bằng AES-128-CBC.

  * **Tham số:**
      * `ciphertext` (`bytes`): Dữ liệu đã mã hóa.
      * `key` (`bytes`): Khóa giải mã, phải giống hệt khóa mã hóa và dài 16 bytes.
      * `iv` (`bytes`): Initialization Vector, phải giống hệt IV đã dùng để mã hóa và dài 16 bytes.
  * **Trả về:**
      * Một đối tượng `bytes` chứa dữ liệu gốc đã được giải mã.
      * `None` nếu có lỗi (ví dụ: sai khóa, dữ liệu hỏng, hoặc lỗi padding).

#### `sha256(data: bytes) -> bytes` 

Băm dữ liệu bằng thuật toán SHA-256.

-----

### **Ví dụ hoàn chỉnh**

Dưới đây là một script Python đầy đủ để bạn có thể chạy thử ngay.

```python
import ctypes
import os
from typing import Optional

# Tên file thư viện .so
LIB_PATH = './libbmc_cryptographic.so'

class BCrypto:
    """
    Lớp Python wrapper để làm việc với thư viện C đa năng.
    """
    def __init__(self, library_path: str):
        if not os.path.exists(library_path):
            raise FileNotFoundError(f"Thư viện không được tìm thấy tại: {library_path}")
        
        self.lib = ctypes.CDLL(library_path)
        self._configure_functions() 
        print("Thư viện bmc_crypto đã được nạp thành công.") 

    def _configure_functions(self):
        """Cấu hình chữ ký các hàm C dựa trên bmc_crypto.h""" 
        
        # --- AES Functions ---
        self.lib.bmc_aes_get_padded_size.argtypes = [ctypes.c_size_t]
        self.lib.bmc_aes_get_padded_size.restype = ctypes.c_size_t
        
        self.lib.bmc_aes128_cbc_encrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, 
            ctypes.c_void_p, ctypes.c_void_p
        
            self.lib.bmc_aes128_cbc_encrypt.restype = ctypes.c_int 

        self.lib.bmc_aes128_cbc_decrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t)
        
        self.lib.bmc_aes128_cbc_decrypt.restype = ctypes.c_int 

        # --- SHA-256 Function ---
        self.lib.bmc_sha256.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p] 
        self.lib.bmc_sha256.restype = None 


    def aes_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Hàm mã hóa AES-128-CBC tiện lợi."""
        if len(key) != 16 or len(iv) != 16:
            print("Lỗi: Key và IV phải dài đúng 16 bytes.") 
            return None

        encrypted_size = self.lib.bmc_aes_get_padded_size(len(plaintext))
        encrypted_buf = ctypes.create_string_buffer(encrypted_size)
        
        result = self.lib.bmc_aes128_cbc_encrypt(
            plaintext, len(plaintext), key, iv, encrypted_buf
        )
        if result != 0: return None
        return encrypted_buf.raw 

    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Hàm giải mã AES-128-CBC tiện lợi."""
        if len(key) != 16 or len(iv) != 16:
            print("Lỗi: Key và IV phải dài đúng 16 bytes.")
            return None

        decrypted_buf = ctypes.create_string_buffer(len(ciphertext))
        actual_len = ctypes.c_size_t(0)
        
        result = self.lib.bmc_aes128_cbc_decrypt(
            ciphertext, len(ciphertext), key, iv,
            decrypted_buf, ctypes.byref(actual_len)
        )
        if result != 0: return None
        return decrypted_buf.raw[:actual_len.value]

    def sha256(self, data: bytes) -> bytes:
        """Hàm băm SHA-256 tiện lợi."""
        hash_buf = ctypes.create_string_buffer(32) 
        self.lib.bmc_sha256(data, len(data), hash_buf)
        return hash_buf.raw

# --- Kịch bản Test ---
if __name__ == "__main__":
    try:
        crypto = BCrypto(LIB_PATH)
        
        # --- Test AES ---
        print("\n--- TESTING AES-128-CBC ---")
        plaintext_aes = b"Testing the final modular library in Python!"
        key_aes = b'a-16-byte-secret' 
        iv_aes  = b'a-16-byte-vector' 

        encrypted = crypto.aes_encrypt(plaintext_aes, key_aes, iv_aes)
        if encrypted:
            print(f"AES Encrypted (hex): {encrypted.hex()}")
            decrypted = crypto.aes_decrypt(encrypted, key_aes, iv_aes)
            if decrypted:
                print(f"AES Decrypted: {decrypted.decode()}")
                assert plaintext_aes == decrypted 
                print("✅ AES Test PASSED") 
        
        # --- Test SHA-256 ---
        print("\n--- TESTING SHA-256 ---")
        input_sha = b"abc"
        expected_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        
        actual_hash = crypto.sha256(input_sha)
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
