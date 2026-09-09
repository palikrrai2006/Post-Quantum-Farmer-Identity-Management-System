// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BiometricRegistry
/// @notice Anchors IPFS CIDs and integrity hashes for PM-KISAN farmer
///         biometric registration packages, with three-role access control:
///         Admin (registers records, requires physical presence in practice),
///         Government (read-only audit access), and Farmer (self-service read).
contract BiometricRegistry {
    enum Role {
        None,
        Admin,
        Government,
        Farmer
    }

    struct Record {
        string cid;
        string templateHash;
        uint256 timestamp;
        bool exists;
    }

    address public owner;
    mapping(address => Role) public roles;
    mapping(string => Record) private records;
    mapping(string => address) public farmerIdToAddress;

    event RoleAssigned(address indexed account, Role role);
    event RecordRegistered(string indexed farmerId, string cid, string templateHash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "BiometricRegistry: caller is not the owner");
        _;
    }

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.Admin, "BiometricRegistry: caller is not an Admin");
        _;
    }

    modifier onlyAuthorizedReader(string memory farmerId) {
        require(
            roles[msg.sender] == Role.Admin || roles[msg.sender] == Role.Government
                || farmerIdToAddress[farmerId] == msg.sender,
            "BiometricRegistry: caller is not authorized to read this record"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        roles[msg.sender] = Role.Admin;
        emit RoleAssigned(msg.sender, Role.Admin);
    }

    /// @notice Assign a role to an account. Restricted to the contract owner.
    /// @param account The address to assign a role to.
    /// @param role The role to assign (Admin, Government, or Farmer).
    function assignRole(address account, Role role) external onlyOwner {
        roles[account] = role;
        emit RoleAssigned(account, role);
    }

    /// @notice Link a farmer ID to the on-chain address that may self-service it.
    /// @param farmerId The unique farmer identifier (e.g., "FRM001").
    /// @param farmerAddress The address belonging to that farmer.
    function linkFarmerAddress(string calldata farmerId, address farmerAddress) external onlyAdmin {
        farmerIdToAddress[farmerId] = farmerAddress;
    }

    /// @notice Register (or update) a farmer's biometric registration package anchor.
    /// @dev Requires the caller to hold the Admin role, reflecting the
    ///      requirement of physical presence during registration.
    /// @param farmerId The unique farmer identifier.
    /// @param cid The IPFS CID of the registration package directory.
    /// @param templateHash The SHA3-256 hex digest of the encrypted package.
    function registerRecord(string calldata farmerId, string calldata cid, string calldata templateHash)
        external
        onlyAdmin
    {
        records[farmerId] = Record({cid: cid, templateHash: templateHash, timestamp: block.timestamp, exists: true});
        emit RecordRegistered(farmerId, cid, templateHash, block.timestamp);
    }

    /// @notice Retrieve a farmer's anchored registration record.
    /// @param farmerId The unique farmer identifier to look up.
    /// @return cid The IPFS CID of the registration package directory.
    /// @return templateHash The SHA3-256 hex digest of the encrypted package.
    /// @return timestamp The block timestamp at which the record was registered.
    function getRecord(string calldata farmerId)
        external
        view
        onlyAuthorizedReader(farmerId)
        returns (string memory cid, string memory templateHash, uint256 timestamp)
    {
        Record storage record = records[farmerId];
        require(record.exists, "BiometricRegistry: no record found for this farmer ID");
        return (record.cid, record.templateHash, record.timestamp);
    }

    /// @notice Check whether a record exists for a given farmer ID.
    /// @param farmerId The unique farmer identifier to check.
    /// @return True if a record exists, false otherwise.
    function recordExists(string calldata farmerId) external view returns (bool) {
        return records[farmerId].exists;
    }
}
