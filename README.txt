BMC Cryptographic Library (Updated 26-06-2025)
//// AES CBC MODE
- bmc_aes128_cbc_encrypt(plaintext, len(plaintext), key, iv, encrypted_buf)
- bmc_aes192_cbc_encrypt(plaintext, len(plaintext), key, iv, encrypted_buf)
- bmc_aes256_cbc_encrypt(plaintext, len(plaintext), key, iv, encrypted_buf)
- bmc_aes128_cbc_decrypt(ciphertext, len(ciphertext), key, iv,decrypted_buf, ctypes.byref(actual_len))
- bmc_aes192_cbc_decrypt(ciphertext, len(ciphertext), key, iv,decrypted_buf, ctypes.byref(actual_len))
- bmc_aes256_cbc_decrypt(ciphertext, len(ciphertext), key, iv,decrypted_buf, ctypes.byref(actual_len))

//// AES ECB MODE
- bmc_aes128_ecb_encrypt(plaintext, len, key[16], ciphertext);
- bmc_aes128_ecb_decrypt(ciphertext, len, key[16], plaintext, out_len);
- bmc_aes192_ecb_encrypt(plaintext, len, key[24], ciphertext);
- bmc_aes192_ecb_decrypt(ciphertext, len, key[24], plaintext, out_len);
- bmc_aes256_ecb_encrypt(plaintext, len, key[32], ciphertext);
- bmc_aes256_ecb_decrypt(ciphertext, len, key[32], plaintext, out_len);

//// AES CTR MODE
- bmc_aes128_ctr_encrypt(plaintext, len, key[16], iv[16], ciphertext_out);
- bmc_aes128_ctr_decrypt(ciphertext, len, key[16], iv[16], plaintext_out);
- bmc_aes192_ctr_encrypt(plaintext, len, key[24], iv[16], ciphertext_out);
- bmc_aes192_ctr_decrypt(ciphertext, len, key[24], iv[16], plaintext_out);
- bmc_aes256_ctr_encrypt(plaintext, len, key[32], iv[16], ciphertext_out);
- bmc_aes256_ctr_decrypt(ciphertext, len, key[32], iv[16], plaintext_out);

//// SHA-256
- bmc_sha256(data, len, output[32])

//// SHA3
- bmc_sha3_256(data, len, output[32]);
- bmc_sha3_384(data, len, output[48]);
- bmc_sha3_512(data, len, output[64]);


Hướng dẫn sử dụng (API) - Python
Cách tốt nhất để sử dụng thư viện là thông qua lớp BCrypto được cung cấp trong ví dụ dưới đây.
1. Khởi tạo

import ctypes
import os
# Đường dẫn mặc định đến thư viện
LIB_PATH = './libbmc_cryptographic.so'
# Khởi tạo đối tượng từ lớp BCrypto
crypto = BCrypto(LIB_PATH)

2. Lớp BCrypto

- aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes | None

Tham số:
plaintext (bytes): Dữ liệu gốc cần mã hóa.
key (bytes): Khóa mã hóa. Bắt buộc phải dài 16 bytes cho AES-128.
iv (bytes): Initialization Vector. Bắt buộc phải dài 16 bytes.
Trả về:
Một đối tượng bytes chứa dữ liệu đã được mã hóa.
None nếu có lỗi xảy ra.

- aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None

Tham số:
ciphertext (bytes): Dữ liệu đã được mã hóa.
key (bytes): Khóa giải mã. Phải giống hệt khóa đã dùng để mã hóa và dài 16 bytes.
iv (bytes): Initialization Vector. Phải giống hệt IV đã dùng để mã hóa và dài 16 bytes.
Trả về:
Một đối tượng bytes chứa dữ liệu gốc đã được giải mã.
None nếu có lỗi (ví dụ: sai khóa, dữ liệu hỏng, hoặc lỗi padding).

- sha256 (data: bytes) -> bytes

Ví dụ hoàn chỉnh

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
        ]
        self.lib.bmc_aes128_cbc_encrypt.restype = ctypes.c_int

        self.lib.bmc_aes128_cbc_decrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t)
        ]
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