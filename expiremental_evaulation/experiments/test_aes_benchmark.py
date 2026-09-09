from pathlib import Path

from crypto.aes_utils import (
    generate_aes_key,
    encrypt_template_file,
    decrypt_template_file,
)

from config import (
    RAW_TEMPLATES_DIR,
    ENCRYPTED_TEMPLATES_DIR,
)


def main():
    template_path = RAW_TEMPLATES_DIR / "101_1_template.txt"
    encrypted_path = ENCRYPTED_TEMPLATES_DIR / "FRM001.enc"

    print("=" * 60)
    print("AES-256-GCM BENCHMARK")
    print("=" * 60)

    # Generate a fresh AES key
    key = generate_aes_key()

    # Encrypt
    enc_result = encrypt_template_file(
        template_path=template_path,
        key=key,
        output_path=encrypted_path,
    )

    # Decrypt
    dec_result = decrypt_template_file(
        encrypted_path=encrypted_path,
        key=key,
    )

    # Verify integrity
    original = template_path.read_bytes()

    print(f"Template               : {template_path.name}")
    print(f"Encrypted File         : {encrypted_path.name}")
    print()

    print("----- Encryption -----")
    print(f"Plaintext Size         : {enc_result.plaintext_size_bytes} bytes")
    print(f"Ciphertext Size        : {enc_result.ciphertext_size_bytes} bytes")
    print(f"AES Key Size           : {enc_result.key_size_bytes} bytes")
    print(f"Nonce Size             : {enc_result.nonce_size_bytes} bytes")
    print(f"Authentication Tag     : {enc_result.tag_size_bytes} bytes")
    print(f"Encryption Time        : {enc_result.encryption_time_seconds * 1000:.4f} ms")
    print()

    print("----- Decryption -----")
    print(f"Recovered Size         : {dec_result.plaintext_size_bytes} bytes")
    print(f"Decryption Time        : {dec_result.decryption_time_seconds * 1000:.4f} ms")
    print()

    if original == dec_result.plaintext:
        print("Integrity Check        : PASSED")
    else:
        print("Integrity Check        : FAILED")


if __name__ == "__main__":
    main()