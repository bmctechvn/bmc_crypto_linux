
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
LIB_PATH = './libbmc_crypto.so'

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
        """Cấu hình chữ ký cho các hàm C dựa trên bmc_crypto.h"""
        
        # --- Cấu hình cho hàm AES-256-CTR ---
        self.lib.bmc_aes256_ctr_xcrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, 
            ctypes.c_void_p, ctypes.c_void_p, 
            ctypes.c_void_p
        ]
        self.lib.bmc_aes256_ctr_xcrypt.restype = ctypes.c_int
        
        # ... bạn có thể thêm cấu hình cho các hàm khác ở đây ...

    def aes256_ctr_xcrypt(self, data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Hàm tiện lợi để gọi bmc_aes256_ctr_xcrypt."""
        
        if len(key) != 32:
            print("Lỗi: Key cho AES-256 phải dài đúng 32 bytes.")
            return None
        if len(iv) != 16:
            print("Lỗi: IV phải dài đúng 16 bytes.")
            return None

        # Trong CTR, output size luôn bằng input size
        output_buf = ctypes.create_string_buffer(len(data))
        
        result = self.lib.bmc_aes256_ctr_xcrypt(
            data, len(data), key, iv, output_buf
        )
        
        if result != 0:
            print(f"Lỗi khi thực thi hàm C, mã lỗi: {result}")
            return None
            
        return output_buf.raw

# --- Kịch bản Test ---
if __name__ == "__main__":
    try:
        crypto = BCrypto(LIB_PATH)
        
        print("\n--- TESTING AES-256-CTR ---")
        
        # Chuẩn bị dữ liệu
        plaintext = b"This is a test message for AES-256 in Counter Mode."
        # Tạo key 32-byte và IV 16-byte ngẫu nhiên
        key = os.urandom(32) 
        iv  = os.urandom(16)  

        print(f"Plaintext: {plaintext.decode()}")
        print(f"Key (hex): {key.hex()}")
        print(f"IV (hex) : {iv.hex()}")

        # Mã hóa
        print("\n--- Encrypting ---")
        ciphertext = crypto.aes256_ctr_xcrypt(plaintext, key, iv)
        if ciphertext:
            print(f"Ciphertext (hex): {ciphertext.hex()}")

            # Giải mã
            print("\n--- Decrypting ---")
            # CTR dùng cùng một hàm và cùng một bộ key/iv để giải mã
            decrypted_text = crypto.aes256_ctr_xcrypt(ciphertext, key, iv)
            
            if decrypted_text:
                print(f"Decrypted text: {decrypted_text.decode()}")

                # Xác minh
                assert plaintext == decrypted_text
                print("\n✅ TEST PASSED: Dữ liệu giải mã khớp với dữ liệu gốc!")

    except Exception as e:
        print(f"\n❌ Đã có lỗi xảy ra: {e}")
```

### **Lưu ý**

  * **Độ dài Key/IV:** Các hàm tiện lợi trong ví dụ (`aes_encrypt`, `aes_decrypt`) được viết cho AES-128. Bạn có thể dễ dàng tạo thêm các hàm mới (`aes_encrypt_256`,...) để gọi các phiên bản 192/256-bit từ thư viện C.
  * **An toàn luồng (Thread Safety):** Thư viện này không an toàn để sử dụng trên nhiều luồng nếu bạn dùng chung một đối tượng `BCrypto` mà không có cơ chế khóa (locking).

## **Giấy phép**

Dự án này được cấp phép theo Giấy phép MIT.
