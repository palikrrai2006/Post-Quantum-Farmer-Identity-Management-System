import csv
import shutil
import time
from pathlib import Path

import config
from blockchain.web3_utils import BlockchainManager
from storage import ipfs_utils

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

CSV_FILE = RESULTS_DIR / "ipfs_results.csv"


def batch_ipfs():

    bm = BlockchainManager()

    package_root = Path(config.PACKAGES_DIR)

    users = sorted(
        [
            d.name
            for d in package_root.iterdir()
            if d.is_dir() and d.name.isdigit()
        ]
    )

    print("=" * 60)
    print("IPFS BATCH PERFORMANCE EVALUATION")
    print("=" * 60)

    rows = []

    upload_times = []
    download_times = []
    package_sizes = []

    success = 0

    start = time.perf_counter()

    for user in users:

        try:

            cid = bm.get_cid(user)

            download_dir = package_root / f"temp_download_{user}"

            if download_dir.exists():
                shutil.rmtree(download_dir)

            result = ipfs_utils.download_package(
                cid,
                download_dir
            )

            size = sum(
                f.stat().st_size
                for f in download_dir.rglob("*")
                if f.is_file()
            )

            upload_time = 0.0

            metadata = package_root / user / "upload_metadata.json"

            if metadata.exists():
                import json

                with open(metadata) as f:
                    upload_time = json.load(f).get(
                        "upload_time_milliseconds",
                        0.0
                    )

            rows.append(
                {
                    "user": user,
                    "cid": cid,
                    "package_size_bytes": size,
                    "upload_ms": upload_time,
                    "download_ms": result.download_time_milliseconds,
                }
            )

            upload_times.append(upload_time)
            download_times.append(result.download_time_milliseconds)
            package_sizes.append(size)

            success += 1

            shutil.rmtree(download_dir)

        except Exception as e:

            print(user, e)

    elapsed = time.perf_counter() - start

    with open(CSV_FILE, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(rows)

    print("\n")
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"Users Evaluated          : {success}")

    print(f"Average Upload Time      : {sum(upload_times)/len(upload_times):.2f} ms")

    print(f"Average Download Time    : {sum(download_times)/len(download_times):.2f} ms")

    print(f"Minimum Download Time    : {min(download_times):.2f} ms")

    print(f"Maximum Download Time    : {max(download_times):.2f} ms")

    print(f"Average Package Size     : {sum(package_sizes)/len(package_sizes):.2f} Bytes")

    print(f"Total Execution Time     : {elapsed:.2f} sec")

    print(f"Throughput               : {success/elapsed:.2f} packages/sec")

    print(f"Success Rate             : {(success/len(users))*100:.2f}%")

    print(f"\nCSV Saved : {CSV_FILE}")


if __name__ == "__main__":
    batch_ipfs()