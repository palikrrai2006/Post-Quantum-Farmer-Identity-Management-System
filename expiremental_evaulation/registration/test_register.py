import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from registration.processor import register_user

def run():
    user_id = "user_001"
    template_path = config.RAW_TEMPLATES_DIR / "sample.dat"
    
    if not template_path.exists():
        print(f"File missing: {template_path}")
        return

    result = register_user(user_id, template_path)
    
    print("\n" + "="*40)
    print("PHASE 13.7: REGISTRATION COMPLETE")
    print("="*40)
    print(f"User ID:    {result.user_id}")
    print(f"CID:        {result.cid}")
    print(f"TX Hash:    {result.tx_hash}")
    print(f"Total Time: {result.time_ms_total:.2f}ms")
    print("="*40)

if __name__ == "__main__":
    run()