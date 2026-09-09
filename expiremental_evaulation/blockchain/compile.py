"""blockchain/compile.py

Compiles the Solidity contract and generates ABI/BIN files.
Ensures EVM compatibility with local Ganache nodes.
"""

import json
import os
from solcx import compile_standard, install_solc

def compile_contract():
    # 1. Install the Solidity compiler version
    # '0.8.20' is required for the pragma used in your contract
    install_solc('0.8.20')
    
    # 2. Read the source file
    contract_path = os.path.join('blockchain', 'contract.sol')
    with open(contract_path, 'r') as f:
        source = f.read()
    
    # 3. Configure compilation settings
    # 'evmVersion': 'london' ensures compatibility with most local Ganache versions
    input_data = {
        "language": "Solidity",
        "sources": {"contract.sol": {"content": source}},
        "settings": {
            "evmVersion": "london",
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode"]
                }
            }
        }
    }
    
    print("Compiling contract...")
    compiled = compile_standard(input_data, solc_version='0.8.20')
    
    # 4. Check for errors
    if 'errors' in compiled:
        for error in compiled['errors']:
            print(f"{error['severity']}: {error['message']}")
        if any(e['severity'] == 'error' for e in compiled['errors']):
            print("Compilation failed.")
            return

    # 5. Extract and save artifacts
    # Assumes your contract name in contract.sol is 'BiometricRegistry'
    contract_data = compiled['contracts']['contract.sol']['BiometricRegistry']
    abi = contract_data['abi']
    bytecode = contract_data['evm']['bytecode']['object']
    
    abi_path = os.path.join('blockchain', 'contract_abi.json')
    bin_path = os.path.join('blockchain', 'contract.bin')
    
    with open(abi_path, 'w') as f:
        json.dump(abi, f, indent=4)
        
    with open(bin_path, 'w') as f:
        f.write(bytecode)
        
    print(f"Compilation successful!")
    print(f"ABI saved to: {abi_path}")
    print(f"Bytecode saved to: {bin_path}")

if __name__ == "__main__":
    compile_contract()