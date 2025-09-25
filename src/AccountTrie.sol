// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solidity-merkle-trees/trie/ethereum/RLPReader.sol";
import "solidity-merkle-trees/MerklePatricia.sol";

library AccountTrie {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

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
        storageRoot = bytes32(accountData[2].toUint());
        codeHash = bytes32(accountData[3].toUint());
    }
}
