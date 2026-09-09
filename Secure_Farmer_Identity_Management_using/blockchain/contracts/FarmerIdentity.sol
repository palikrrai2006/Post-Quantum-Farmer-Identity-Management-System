// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FarmerIdentity
/// @notice Stores ONLY integrity references for farmer fingerprint records:
///         farmer_id, finger_position, IPFS CID, SHA3-256 integrity hash,
///         timestamp, and status. Never stores raw biometrics, templates,
///         or any cryptographic secret key.
contract FarmerIdentity {
    enum Status { REGISTERED, REVOKED }

    struct FingerprintRecord {
        string farmerId;
        string fingerPosition;
        string ipfsCid;
        bytes32 integrityHash;   // SHA3-256 digest (32 bytes)
        uint256 timestamp;
        Status status;
        address recordedBy;
        bool exists;
    }

    // key = keccak256(farmerId, fingerPosition) -> record
    mapping(bytes32 => FingerprintRecord) private records;

    // Track which keys belong to a farmer, for enumeration
    mapping(string => bytes32[]) private farmerRecordKeys;

    address public owner;

    event FingerprintRegistered(
        string indexed farmerIdIndexed,
        string farmerId,
        string fingerPosition,
        string ipfsCid,
        bytes32 integrityHash,
        uint256 timestamp
    );

    event FingerprintUpdated(
        string farmerId,
        string fingerPosition,
        string newIpfsCid,
        bytes32 newIntegrityHash,
        uint256 timestamp
    );

    event FingerprintRevoked(string farmerId, string fingerPosition, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "FarmerIdentity: caller is not the contract owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function _key(string memory farmerId, string memory fingerPosition) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(farmerId, "|", fingerPosition));
    }

    /// @notice Register a new fingerprint record. Reverts if farmerId+fingerPosition already exists
    ///         (use updateFingerprintRecord for authorized updates instead).
    function registerFingerprintRecord(
        string memory farmerId,
        string memory fingerPosition,
        string memory ipfsCid,
        bytes32 integrityHash
    ) public returns (bool) {
        bytes32 key = _key(farmerId, fingerPosition);
        require(!records[key].exists, "FarmerIdentity: record already exists for this farmer+finger");

        records[key] = FingerprintRecord({
            farmerId: farmerId,
            fingerPosition: fingerPosition,
            ipfsCid: ipfsCid,
            integrityHash: integrityHash,
            timestamp: block.timestamp,
            status: Status.REGISTERED,
            recordedBy: msg.sender,
            exists: true
        });

        farmerRecordKeys[farmerId].push(key);

        emit FingerprintRegistered(farmerId, farmerId, fingerPosition, ipfsCid, integrityHash, block.timestamp);
        return true;
    }

    /// @notice Retrieve a fingerprint record's on-chain reference data.
    function getFingerprintRecord(string memory farmerId, string memory fingerPosition)
        public
        view
        returns (
            string memory ipfsCid,
            bytes32 integrityHash,
            uint256 timestamp,
            Status status,
            address recordedBy
        )
    {
        bytes32 key = _key(farmerId, fingerPosition);
        require(records[key].exists, "FarmerIdentity: record does not exist");
        FingerprintRecord memory r = records[key];
        return (r.ipfsCid, r.integrityHash, r.timestamp, r.status, r.recordedBy);
    }

    /// @notice Authorized update — e.g. re-enrollment after a legitimate correction.
    function updateFingerprintRecord(
        string memory farmerId,
        string memory fingerPosition,
        string memory newIpfsCid,
        bytes32 newIntegrityHash
    ) public returns (bool) {
        bytes32 key = _key(farmerId, fingerPosition);
        require(records[key].exists, "FarmerIdentity: record does not exist");

        records[key].ipfsCid = newIpfsCid;
        records[key].integrityHash = newIntegrityHash;
        records[key].timestamp = block.timestamp;
        records[key].status = Status.REGISTERED;

        emit FingerprintUpdated(farmerId, fingerPosition, newIpfsCid, newIntegrityHash, block.timestamp);
        return true;
    }

    function revokeFingerprintRecord(string memory farmerId, string memory fingerPosition) public returns (bool) {
        bytes32 key = _key(farmerId, fingerPosition);
        require(records[key].exists, "FarmerIdentity: record does not exist");
        records[key].status = Status.REVOKED;
        emit FingerprintRevoked(farmerId, fingerPosition, block.timestamp);
        return true;
    }

    function fingerprintRecordExists(string memory farmerId, string memory fingerPosition) public view returns (bool) {
        return records[_key(farmerId, fingerPosition)].exists;
    }

    function getFarmerFingerCount(string memory farmerId) public view returns (uint256) {
        return farmerRecordKeys[farmerId].length;
    }
}
