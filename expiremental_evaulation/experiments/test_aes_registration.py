from crypto.aes_utils import encrypt_template_file

result = encrypt_template_file(
    r"C:\Users\palikrrai\Desktop\MAJOR PROJECT\data\templates\raw_templates\101_1_template.txt",
    "FRM001"
)

print("\n========== AES REGISTRATION ==========")

for k, v in result["metrics"].items():
    print(f"{k}: {v}")

print("\nEncrypted Template:")
print(result["encrypted_path"])

print("\nMetadata:")
print(result["metadata_path"])