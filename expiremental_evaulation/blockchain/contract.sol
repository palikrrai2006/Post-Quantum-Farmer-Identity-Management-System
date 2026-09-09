// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BiometricRegistry
 * @dev Manages the mapping of User IDs to IPFS CIDs for biometric data packages.
 * Includes Access Control to ensure only the authorized server can store data.
 */
contract BiometricRegistry {
    
    struct RegistrationRecord {
        string cid;
        uint256 timestamp;
        bool exists;
    }

    // Mapping from userId string to registration details
    mapping(string => RegistrationRecord) private registry;
    
    // The owner is the address that deployed the contract
    address public owner;

    event CIDStored(string indexed userId, string cid, uint256 timestamp);
    event CIDUpdated(string indexed userId, string oldCid, string newCid, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the authorized server");
        _;
    }

    /**
     * @notice Stores the IPFS CID for a given user.
     * @param userId The unique identifier for the user.
     * @param cid The IPFS Content Identifier of the registration package.
     */
    function storeCID(string memory userId, string memory cid) public onlyOwner {
        require(bytes(cid).length > 0, "CID cannot be empty");
        
        if (registry[userId].exists) {
            emit CIDUpdated(userId, registry[userId].cid, cid, block.timestamp);
        } else {
            emit CIDStored(userId, cid, block.timestamp);
        }

        registry[userId] = RegistrationRecord({
            cid: cid,
            timestamp: block.timestamp,
            exists: true
        });
    }

    /**
     * @notice Retrieves the CID associated with a user.
     * @param userId The unique identifier for the user.
     */
    function getCID(string memory userId) public view returns (string memory) {
        require(registry[userId].exists, "User ID not found in registry");
        return registry[userId].cid;
    }

    /**
     * @notice Returns the registration timestamp.
     */
    function getRegistrationTimestamp(string memory userId) public view returns (uint256) {
        require(registry[userId].exists, "User ID not found in registry");
        return registry[userId].timestamp;
    }

    /**
     * @notice Allows ownership transfer if the server infra changes.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner is the zero address");
        owner = newOwner;
    }
}