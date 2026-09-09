"""blockchain/deploy.py

Deploys the BiometricRegistry contract to the local blockchain.
"""

import json
from web3 import Web3
import config

def deploy():
    w3 = Web3(Web3.HTTPProvider(config.BLOCKCHAIN_RPC_URL))
    
    # Load compiled artifacts
    with open('blockchain/contract_abi.json', 'r') as f:
        abi = json.load(f)
    with open('blockchain/contract.bin', 'r') as f:
        bytecode = f.read().strip()
    
    # Set deployment account
    account = w3.eth.account.from_key(config.BLOCKCHAIN_PRIVATE_KEY)
    
    # Build Deployment Transaction
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    txn = contract.constructor().build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': config.BLOCKCHAIN_GAS_LIMIT,
        'gasPrice': w3.eth.gas_price
    })
    
    # Sign and Send
    signed_txn = w3.eth.account.sign_transaction(txn, config.BLOCKCHAIN_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print(f"Contract deployed at address: {tx_receipt.contractAddress}")
    return tx_receipt.contractAddress

if __name__ == "__main__":
    address = deploy()
    print("Update config.py with this address.")