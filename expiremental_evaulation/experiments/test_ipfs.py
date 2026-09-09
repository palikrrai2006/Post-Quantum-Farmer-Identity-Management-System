from pathlib import Path
from storage.ipfs_utils import upload_package, download_package

package = Path("packages/test_e2e_package")

upload = upload_package(package)

print("CID:", upload.cid)
print("Upload Time:", upload.upload_time_milliseconds, "ms")

download = download_package(
    upload.cid,
    Path("downloads/test_package")
)

print("Download Time:", download.download_time_milliseconds, "ms")