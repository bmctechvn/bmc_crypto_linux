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