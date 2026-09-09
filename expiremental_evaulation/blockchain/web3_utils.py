"""blockchain/web3_utils.py

Provides connectivity and interaction utilities for the BiometricRegistry smart contract.
Updated for web3.py v7+ compatibility.
"""

import json
import logging
from web3 import Web3
# NEW: Correct import for PoA middleware in web3.py v7+
from web3.middleware import ExtraDataToPOAMiddleware
import config

logger = logging.getLogger(__name__)

class BlockchainManager:
    def __init__(self) -> None:
        """Initializes the connection to the blockchain and loads the contract."""
        self.w3 = Web3(Web3.HTTPProvider(config.BLOCKCHAIN_RPC_URL))
        
        # NEW: Inject the class-based middleware at layer 0
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        
        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to blockchain at {config.BLOCKCHAIN_RPC_URL}")
        
        # Load ABI from file
        with open(config.BLOCKCHAIN_CONTRACT_ABI_PATH, 'r') as f:
            self.abi = json.load(f)
        
        # Initialize contract instance
        self.contract = self.w3.eth.contract(
            address=config.BLOCKCHAIN_CONTRACT_ADDRESS,
            abi=self.abi
        )
        
        # Setup account
        self.account = self.w3.eth.account.from_key(config.BLOCKCHAIN_PRIVATE_KEY)

    def store_cid(self, user_id: str, cid: str) -> str:
        """Stores the IPFS CID on the blockchain."""
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        
        # Build transaction
        txn = self.contract.functions.storeCID(user_id, cid).build_transaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': config.BLOCKCHAIN_GAS_LIMIT,
            'gasPrice': self.w3.eth.gas_price,
            "chainId": self.w3.eth.chain_id,
        })
        
        # Sign and send
        signed_txn = self.w3.eth.account.sign_transaction(txn, config.BLOCKCHAIN_PRIVATE_KEY)
        # Note: Use .raw_transaction (snake_case) as per current web3.py API
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        logger.info(f"Transaction sent: {self.w3.to_hex(tx_hash)}")
        return self.w3.to_hex(tx_hash)

    def get_cid(self, user_id: str) -> str:
        """Retrieves the IPFS CID associated with a user."""
        return self.contract.functions.getCID(user_id).call()