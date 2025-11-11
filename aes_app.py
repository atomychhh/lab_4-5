#!/usr/bin/env python3
"""
AES-256 Encryption System - Complete Implementation
All-in-one file for easy deployment

Requirements: pip3 install cryptography
Usage: python3 aes_complete.py
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding as sym_padding
import hmac
import hashlib
import time

class AESCryptoModule:
    """Comprehensive AES encryption module supporting CBC and GCM modes"""
    SUPPORTED_MODES = ['CBC', 'GCM']
    KEY_LENGTH = 32  # AES-256
    SALT_LENGTH = 32
    IV_LENGTH = 16
    GCM_NONCE_LENGTH = 12
    GCM_TAG_LENGTH = 16
    PBKDF2_ITERATIONS = 600000

    def __init__(self, log_file: str = 'aes_crypto.log'):
        self.current_mode = 'GCM'
        self.setup_logging(log_file)
        self.key_storage = {}
        self.logger.info("AES Crypto Module initialized")

    def setup_logging(self, log_file: str):
        self.logger = logging.getLogger('AESCryptoModule')
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(self.SALT_LENGTH)
            self.logger.info("Generated new salt for key derivation")
        self.logger.debug(f"Deriving key with PBKDF2 (iterations: {self.PBKDF2_ITERATIONS})")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        key_fingerprint = hashlib.sha256(key).hexdigest()[:16]
        self.logger.info(f"Key derived successfully (fingerprint: {key_fingerprint})")
        return key, salt

    def encrypt_cbc(self, plaintext: bytes, key: bytes) -> Dict:
        try:
            iv = os.urandom(self.IV_LENGTH)
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
            self.logger.info(f"CBC encryption successful (size: {len(ciphertext)} bytes)")
            return {
                'ciphertext': ciphertext,
                'iv': iv,
                'mac': mac,
                'mode': 'CBC'
            }
        except Exception as e:
            self.logger.error(f"CBC encryption failed: {str(e)}", exc_info=True)
            raise

    def decrypt_cbc(self, encrypted_data: Dict, key: bytes) -> bytes:
        try:
            ciphertext = encrypted_data['ciphertext']
            iv = encrypted_data['iv']
            provided_mac = encrypted_data['mac']
            expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(provided_mac, expected_mac):
                self.logger.error("CBC decryption failed: HMAC verification failed")
                raise ValueError("Authentication failed: Data has been tampered with")
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            self.logger.info(f"CBC decryption successful (size: {len(plaintext)} bytes)")
            return plaintext
        except Exception as e:
            self.logger.error(f"CBC decryption failed: {str(e)}", exc_info=True)
            raise

    def encrypt_gcm(self, plaintext: bytes, key: bytes, associated_data: bytes = b'') -> Dict:
        try:
            nonce = os.urandom(self.GCM_NONCE_LENGTH)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
            actual_ciphertext = ciphertext[:-self.GCM_TAG_LENGTH]
            tag = ciphertext[-self.GCM_TAG_LENGTH:]
            self.logger.info(f"GCM encryption successful (size: {len(actual_ciphertext)} bytes)")
            return {
                'ciphertext': actual_ciphertext,
                'nonce': nonce,
                'tag': tag,
                'mode': 'GCM'
            }
        except Exception as e:
            self.logger.error(f"GCM encryption failed: {str(e)}", exc_info=True)
            raise

    def decrypt_gcm(self, encrypted_data: Dict, key: bytes, associated_data: bytes = b'') -> bytes:
        try:
            ciphertext = encrypted_data['ciphertext']
            nonce = encrypted_data['nonce']
            tag = encrypted_data['tag']
            ciphertext_with_tag = ciphertext + tag
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            self.logger.info(f"GCM decryption successful (size: {len(plaintext)} bytes)")
            return plaintext
        except Exception as e:
            self.logger.error(f"GCM decryption failed: {str(e)}", exc_info=True)
            raise

    def encrypt_file(self, input_path: str, output_path: str, password: str, 
                     mode: str = 'GCM', associated_data: bytes = b'') -> Dict:
        start_time = time.time()
        try:
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            file_size = len(plaintext)
            self.logger.info(f"Encrypting file: {input_path} ({file_size} bytes) using {mode} mode")
            key, salt = self.derive_key(password)
            if mode.upper() == 'CBC':
                encrypted_data = self.encrypt_cbc(plaintext, key)
            elif mode.upper() == 'GCM':
                encrypted_data = self.encrypt_gcm(plaintext, key, associated_data)
            else:
                raise ValueError(f"Unsupported mode: {mode}")
            metadata = {
                'mode': mode.upper(),
                'salt': salt,
                'original_size': file_size,
                'encrypted_size': len(encrypted_data['ciphertext']),
                'timestamp': datetime.now().isoformat()
            }
            with open(output_path, 'wb') as f:
                metadata_json = json.dumps({
                    'mode': metadata['mode'],
                    'salt': salt.hex(),
                    'original_size': metadata['original_size']
                })
                header = metadata_json.encode('utf-8')
                f.write(len(header).to_bytes(4, 'big'))
                f.write(header)
                if mode.upper() == 'CBC':
                    f.write(encrypted_data['iv'])
                    f.write(encrypted_data['mac'])
                    f.write(encrypted_data['ciphertext'])
                else:
                    f.write(encrypted_data['nonce'])
                    f.write(encrypted_data['tag'])
                    f.write(encrypted_data['ciphertext'])
            elapsed = time.time() - start_time
            self.logger.info(f"File encrypted successfully: {output_path} (time: {elapsed:.3f}s)")
            return metadata
        except Exception as e:
            self.logger.error(f"File encryption failed: {str(e)}", exc_info=True)
            raise

    def decrypt_file(self, input_path: str, output_path: str, password: str,
                     associated_data: bytes = b'') -> Dict:
        start_time = time.time()
        try:
            self.logger.info(f"Decrypting file: {input_path}")
            with open(input_path, 'rb') as f:
                header_length = int.from_bytes(f.read(4), 'big')
                header = json.loads(f.read(header_length).decode('utf-8'))
                mode = header['mode']
                salt = bytes.fromhex(header['salt'])
                original_size = header['original_size']
                key, _ = self.derive_key(password, salt)
                if mode == 'CBC':
                    iv = f.read(self.IV_LENGTH)
                    mac = f.read(32)
                    ciphertext = f.read()
                    encrypted_data = {
                        'ciphertext': ciphertext,
                        'iv': iv,
                        'mac': mac,
                        'mode': 'CBC'
                    }
                    plaintext = self.decrypt_cbc(encrypted_data, key)
                else:
                    nonce = f.read(self.GCM_NONCE_LENGTH)
                    tag = f.read(self.GCM_TAG_LENGTH)
                    ciphertext = f.read()
                    encrypted_data = {
                        'ciphertext': ciphertext,
                        'nonce': nonce,
                        'tag': tag,
                        'mode': 'GCM'
                    }
                    plaintext = self.decrypt_gcm(encrypted_data, key, associated_data)
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            elapsed = time.time() - start_time
            self.logger.info(f"File decrypted successfully: {output_path} (time: {elapsed:.3f}s)")
            return {
                'mode': mode,
                'size': len(plaintext),
                'time': elapsed
            }
        except Exception as e:
            self.logger.error(f"File decryption failed: {str(e)}", exc_info=True)
            raise

def demonstrate_tampering_detection():
    print("\n" + "="*60)
    print("DEMONSTRATION: Tampering Detection")
    print("="*60)
    crypto = AESCryptoModule(log_file='tampering_demo.log')
    original_data = b"Important financial transaction: $10,000"
    password = "SecurePassword123!"
    key, salt = crypto.derive_key(password)
    print("\n1. Testing GCM Mode Tampering Detection:")
    print("-" * 50)
    encrypted_gcm = crypto.encrypt_gcm(original_data, key)
    print(f"Original: {original_data.decode()}")
    print(f"Encrypted (GCM): {encrypted_gcm['ciphertext'][:20].hex()}...")
    tampered_gcm = encrypted_gcm.copy()
    tampered_ciphertext = bytearray(tampered_gcm['ciphertext'])
    tampered_ciphertext[10] ^= 0xFF
    tampered_gcm['ciphertext'] = bytes(tampered_ciphertext)
    print("\nAttempting to decrypt tampered ciphertext...")
    try:
        crypto.decrypt_gcm(tampered_gcm, key)
        print("❌ FAILED: Tampering not detected!")
    except Exception as e:
        print(f"✓ SUCCESS: Tampering detected - {type(e).__name__}")
    tampered_tag = encrypted_gcm.copy()
    tampered_tag_bytes = bytearray(tampered_tag['tag'])
    tampered_tag_bytes[0] ^= 0xFF
    tampered_tag['tag'] = bytes(tampered_tag_bytes)
    print("\nAttempting to decrypt with tampered authentication tag...")
    try:
        crypto.decrypt_gcm(tampered_tag, key)
        print("❌ FAILED: Tag tampering not detected!")
    except Exception as e:
        print(f"✓ SUCCESS: Tag tampering detected - {type(e).__name__}")
    print("\n2. Testing CBC Mode Tampering Detection:")
    print("-" * 50)
    encrypted_cbc = crypto.encrypt_cbc(original_data, key)
    print(f"Encrypted (CBC): {encrypted_cbc['ciphertext'][:20].hex()}...")
    tampered_cbc = encrypted_cbc.copy()
    tampered_ciphertext_cbc = bytearray(tampered_cbc['ciphertext'])
    tampered_ciphertext_cbc[10] ^= 0xFF
    tampered_cbc['ciphertext'] = bytes(tampered_ciphertext_cbc)
    print("\nAttempting to decrypt tampered CBC ciphertext...")
    try:
        crypto.decrypt_cbc(tampered_cbc, key)
        print("❌ FAILED: Tampering not detected!")
    except Exception as e:
        print(f"✓ SUCCESS: Tampering detected via HMAC - {type(e).__name__}")
    print("\n" + "="*60)
    print("All tampering attempts were successfully detected!")
    print("="*60)

class AESConsoleApp:
    """Interactive console application for file encryption"""
    def __init__(self):
        self.crypto = AESCryptoModule()
        self.current_mode = 'GCM'
        self.running = True
    def clear_screen(self):
        os.system('clear' if os.name != 'nt' else 'cls')
    def print_header(self):
        print("\n" + "="*70)
        print(" " * 20 + "AES FILE ENCRYPTION SYSTEM")
        print("="*70)
        print(f"Current Mode: {self.current_mode} | Security: AES-256")
        print("="*70 + "\n")
    def print_menu(self):
        print("MAIN MENU:")
        print("-" * 70)
        print("  1. Encrypt File")
        print("  2. Decrypt File")
        print(f"  3. Change Encryption Mode (Current: {self.current_mode})")
        print("  4. Test Tampering Detection")
        print("  5. Help & Documentation")
        print("  6. Exit")
        print("-" * 70)
    def encrypt_file_menu(self):
        print("\n" + "="*70)
        print("FILE ENCRYPTION")
        print("="*70)
        input_path = input("Enter path to file to encrypt: ").strip()
        if not os.path.exists(input_path):
            print(f"❌ Error: File not found: {input_path}")
            input("\nPress Enter to continue...")
            return
        output_path = input("Enter output path (default: input.enc): ").strip()
        if not output_path:
            output_path = input_path + ".enc"
        password = input("Enter encryption password (min 8 chars): ").strip()
        if len(password) < 8:
            print("❌ Error: Password must be at least 8 characters")
            input("\nPress Enter to continue...")
            return
        confirm_password = input("Confirm password: ").strip()
        if password != confirm_password:
            print("❌ Error: Passwords do not match")
            input("\nPress Enter to continue...")
            return
        print(f"\n🔒 Encrypting file using {self.current_mode} mode...")
        try:
            metadata = self.crypto.encrypt_file(
                input_path, 
                output_path, 
                password, 
                mode=self.current_mode
            )
            print("\n" + "="*70)
            print("✅ ENCRYPTION SUCCESSFUL")
            print("="*70)
            print(f"Input:  {input_path}")
            print(f"Output: {output_path}")
            print(f"Mode:   AES-256-{metadata['mode']}")
            print(f"Size:   {metadata['original_size']} bytes → {metadata['encrypted_size']} bytes")
            print("="*70)
        except Exception as e:
            print(f"\n❌ Encryption failed: {str(e)}")
        input("\nPress Enter to continue...")
    def decrypt_file_menu(self):
        print("\n" + "="*70)
        print("FILE DECRYPTION")
        print("="*70)
        input_path = input("Enter path to encrypted file: ").strip()
        if not os.path.exists(input_path):
            print(f"❌ Error: File not found: {input_path}")
            input("\nPress Enter to continue...")
            return
        output_path = input("Enter output path (default: input.dec): ").strip()
        if not output_path:
            if input_path.endswith('.enc'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".dec"
        password = input("Enter decryption password: ").strip()
        print(f"\n🔓 Decrypting file...")
        try:
            result = self.crypto.decrypt_file(input_path, output_path, password)
            print("\n" + "="*70)
            print("✅ DECRYPTION SUCCESSFUL")
            print("="*70)
            print(f"Input:  {input_path}")
            print(f"Output: {output_path}")
            print(f"Mode:   {result['mode']}")
            print(f"Size:   {result['size']} bytes")
            print(f"Time:   {result['time']:.3f}s")
            print("="*70)
        except Exception as e:
            print(f"\n❌ Decryption failed: {str(e)}")
            print("\nPossible reasons:")
            print("  • Incorrect password")
            print("  • File has been tampered with")
            print("  • Corrupted encryption data")
        input("\nPress Enter to continue...")
    def change_mode_menu(self):
        print("\n" + "="*70)
        print("CHANGE ENCRYPTION MODE")
        print("="*70)
        print("\nAvailable modes:")
        print("  1. GCM (Galois/Counter Mode) - ⭐ Recommended")
        print("  2. CBC (Cipher Block Chaining)")
        print("\nMode Comparison:")
        print("-" * 70)
        print("GCM Mode:")
        print("  ✓ Built-in authentication (AEAD)")
        print("  ✓ Parallelizable (faster)")
        print("  ✓ No padding required")
        print("\nCBC Mode:")
        print("  ✓ Wide compatibility")
        print("  • Requires separate HMAC")
        print("  • Sequential processing")
        print("-" * 70)
        choice = input("\nSelect mode (1 or 2): ").strip()
        if choice == '1':
            self.current_mode = 'GCM'
            self.crypto.current_mode = 'GCM'
            print("✓ Mode changed to GCM")
        elif choice == '2':
            self.current_mode = 'CBC'
            self.crypto.current_mode = 'CBC'
            print("✓ Mode changed to CBC")
        else:
            print("❌ Invalid choice")
        input("\nPress Enter to continue...")
    def tampering_test_menu(self):
        print("\n" + "="*70)
        print("TAMPERING DETECTION TEST")
        print("="*70)
        demonstrate_tampering_detection()
        input("\nPress Enter to continue...")
    def help_menu(self):
        print("\n" + "="*70)
        print("HELP & DOCUMENTATION")
        print("="*70)
        print("\nAES File Encryption System v1.0")
        print("\nFeatures:")
        print("  • AES-256 encryption")
        print("  • CBC and GCM modes")
        print("  • PBKDF2 key derivation (600,000 iterations)")
        print("  • Authentication (HMAC/Tag)")
        print("  • Tampering detection")
        print("\nSecurity Standards:")
        print("  • NIST FIPS 197 (AES)")
        print("  • NIST SP 800-38D (GCM)")
        print("  • RFC 2898 (PBKDF2)")
        print("\nBest Practices:")
        print("  ✓ Use GCM for new applications")
        print("  ✓ Strong passwords (12+ chars)")
        print("  ✓ Unique IV/nonce per encryption")
        print("\nLog Files:")
        print("  • aes_crypto.log")
        print("  • tampering_demo.log")
        print("="*70)
        input("\nPress Enter to continue...")
    def run(self):
        while self.running:
            self.clear_screen()
            self.print_header()
            self.print_menu()
            choice = input("\nSelect option (1-6): ").strip()
            if choice == '1':
                self.encrypt_file_menu()
            elif choice == '2':
                self.decrypt_file_menu()
            elif choice == '3':
                self.change_mode_menu()
            elif choice == '4':
                self.tampering_test_menu()
            elif choice == '5':
                self.help_menu()
            elif choice == '6':
                print("\n✅ Thank you for using AES File Encryption System!")
                print("🔒 Stay secure!\n")
                self.running = False
            else:
                print("❌ Invalid option. Please try again.")
                input("\nPress Enter to continue...")

if __name__ == "__main__":
    print("="*70)
    print("AES-256 Cryptographic System")
    print("Supported modes: CBC, GCM")
    print("="*70)
    try:
        app = AESConsoleApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted by user.")
        print("Goodbye! 👋\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
