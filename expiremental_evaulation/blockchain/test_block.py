from blockchain.web3_utils import BlockchainManager

def test():
    manager = BlockchainManager()
    
    # 1. Test Store
    print("Storing CID for user 'test_user_001'...")
    tx_hash = manager.store_cid("test_user_001", "QmTestCid12345")
    print(f"Transaction sent! Hash: {tx_hash}")
    
    # 2. Test Retrieve
    print("Retrieving CID for 'test_user_001'...")
    cid = manager.get_cid("test_user_001")
    print(f"Retrieved CID: {cid}")

    if cid == "QmTestCid12345":
        print("SUCCESS: Blockchain integration is fully operational.")
    else:
        print("FAILURE: Mismatch in stored/retrieved data.")

if __name__ == "__main__":
    test()