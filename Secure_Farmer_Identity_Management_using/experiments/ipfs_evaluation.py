from storage.ipfs_utils import upload_package, download_package

package = {
    "farmer_id": "F001",
    "finger": "LEFT_THUMB",
    "data": "Hello IPFS"
}

result = upload_package(package)

print(result)

download = download_package(result["cid"])

print(download)