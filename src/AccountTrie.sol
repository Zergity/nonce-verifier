// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solidity-merkle-trees/trie/ethereum/RLPReader.sol";
import "solidity-merkle-trees/MerklePatricia.sol";
import "./IBlockHashRecorder.sol";

library AccountTrie {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    /**
     * @notice Extract block number, timestamp and state root from a block header RLP
     * @param blockHeaderRLP RLP encoded block header
     * @return blockNumber The block number
     * @return timestamp The block timestamp
     * @return stateRoot The state root of the block
     */
    function extractFromBlockHeader(
        bytes memory blockHeaderRLP
    ) internal pure returns (
        uint256 blockNumber,
        uint256 timestamp,
        bytes32 stateRoot
    ) {
        RLPReader.RLPItem[] memory headerFields = blockHeaderRLP.toRlpItem().toList();
        require(headerFields.length >= 15, "Invalid block header");
        
        blockNumber = headerFields[8].toUint();
        timestamp = headerFields[11].toUint();
        stateRoot = bytes32(uint256(bytes32(headerFields[3].toBytes())));
    }

    /**
     * @notice Verify an account's state against a state trie root
     * @param account The account address to verify
     * @param stateRoot The state trie root to verify against
     * @param proof The merkle patricia trie proof nodes
     * @return account data in RLP encoded format
     */
    function verify(
        address account,
        bytes32 stateRoot,
        bytes[] memory proof
    ) internal pure returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(abi.encodePacked(account)));
        
        StorageValue[] memory proofs = MerklePatricia.VerifyEthereumProof(
            stateRoot, 
            proof, 
            keys
        );
        
        require(proofs.length == 1, "Invalid proof result length");
        require(proofs[0].value.length > 0, "Account does not exist");
        
        return proofs[0].value;
    }

    /**
     * @notice Decode RLP encoded account data
     * @param accountRLP The RLP encoded account data
     * @return nonce The account nonce
     * @return balance The account balance
     * @return storageRoot The account storage root
     * @return codeHash The account code hash
     */
    function decode(
        bytes memory accountRLP
    ) internal pure returns (
        uint256 nonce,
        uint256 balance,
        bytes32 storageRoot,
        bytes32 codeHash
    ) {
        RLPReader.RLPItem[] memory accountData = accountRLP.toRlpItem().toList();
        require(accountData.length == 4, "Invalid account RLP data");
        
        nonce = accountData[0].toUint();
        balance = accountData[1].toUint();
        storageRoot = abi.decode(accountData[2].toBytes(), (bytes32));
        codeHash = abi.decode(accountData[3].toBytes(), (bytes32));
    }

    /**
     * @notice Verify account nonce, block hash, and block timestamp
     * @param account The account address to verify
     * @param headerRLP The RLP encoded block header
     * @param proof The merkle patricia trie proof nodes for the account
     * @param blockHashRecorder Contract that records historical block hashes
     * @return nonce The account nonce
     * @return timestamp The block timestamp
     */
    function verifyNonceTime(
        address account,
        bytes memory headerRLP,
        bytes[] memory proof,
        address blockHashRecorder
    ) internal view returns (
        uint256 nonce,
        uint256 timestamp
    ) {
        // Extract block header fields
        bytes32 stateRoot;
        uint256 blockNumber;
        (blockNumber, timestamp, stateRoot) = extractFromBlockHeader(headerRLP);

        // Calculate block hash
        bytes32 blockHash = keccak256(headerRLP);

        // Verify block hash
        bytes32 recordedHash = blockhash(blockNumber);
        if (recordedHash == 0) {
            // If not in recent blocks, check BlockHashRecorder
            recordedHash = IBlockHashRecorder(blockHashRecorder).blockHash(blockNumber);
            require(recordedHash != 0, "no block hash available");
        }
        require(recordedHash == blockHash, "block hash mismatch");

        // Verify account state against state root and extract nonce
        bytes memory accountRLP = verify(account, stateRoot, proof);
        (nonce,,,) = decode(accountRLP);
    }
}
