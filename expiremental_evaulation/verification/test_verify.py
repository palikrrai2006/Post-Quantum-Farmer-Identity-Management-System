import sys
from pathlib import Path

# Ensure the project root is in the system path so modules are found
sys.path.append(str(Path(__file__).resolve().parent))

from verification.processor import verify_user

def run_test(user_id: str, image_path: str):
    print(f"==========================================")
    print(f"  PQC-BIOMETRIC AUTHENTICATION TEST")
    print(f"  User ID: {user_id}")
    print(f"  Probe:   {image_path}")
    print(f"==========================================")
    
    try:
        # Trigger the full PQC and Biometric pipeline
        result = verify_user(user_id, Path(image_path))
        
        print("\n--- TEST RESULT ---")
        print(f"Authentication: {'✅ SUCCESS' if result.authentication_success else '❌ FAILED'}")
        print(f"AFIS Score:     {result.sourceafis_score:.2f}")
        
        print("\n--- INTEGRITY CHECKS ---")
        print(f"Signature:      {'VALID' if result.signature_valid else 'INVALID'}")
        print(f"Hash Match:     {'MATCHED' if result.hash_valid else 'MISMATCH'}")
        
        print("\n--- PERFORMANCE METRICS (ms) ---")
        print(f"Total Time:     {result.time_ms_total:.2f}ms")
        print(f"Matching (AFIS):{result.time_ms_afis:.2f}ms")
        
    except Exception as e:
        print(f"\n❌ TEST ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verification/test_verify.py <user_id> <image_path>")
    else:
        run_test(sys.argv[1], sys.argv[2])