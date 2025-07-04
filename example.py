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
        
        # --- Cấu hình cho SHA3-256 ---
        self.lib.bmc_sha3_256.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self.lib.bmc_sha3_256.restype = None # Hàm C trả về void


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
    def sha3_256(self, data: bytes) -> bytes:
        """Hàm băm SHA3-256 tiện lợi."""
        hash_buf = ctypes.create_string_buffer(32) # SHA3-256 output is 32 bytes
        self.lib.bmc_sha3_256(data, len(data), hash_buf)
        return hash_buf.raw
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
         # === Test SHA3-256 ===
        print("\n--- TESTING SHA3-256 ---")
        input_sha = b"" # Test với chuỗi rỗng
        expected_hash = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

        actual_hash = crypto.sha3_256(input_sha)

        print(f"Input: '' (empty string)")
        print(f"Actual Hash:   {actual_hash.hex()}")
        print(f"Expected Hash: {expected_hash}")
        
        assert expected_hash == actual_hash.hex()
        print("✅ SHA3-256 Test PASSED!")
    except Exception as e:
        print(f"\n❌ Đã có lỗi xảy ra: {e}")