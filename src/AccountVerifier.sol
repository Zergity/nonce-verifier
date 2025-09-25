// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solidity-merkle-trees/trie/ethereum/RLPReader.sol";
import "solidity-merkle-trees/MerklePatricia.sol";
import "solidity-merkle-trees/Types.sol";

interface IAccountVerifier {
    function verifyAccount(
        address account,
        uint256 nonce,
        uint256 balance,
        bytes32 accountStateRoot,
        bytes32 stateRoot,
        bytes[] calldata proof
    ) external pure returns (bool);
}

contract AccountVerifier is IAccountVerifier {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    function verifyAccount(
        address account,
        uint256 nonce,
        uint256 balance,
        bytes32 accountStateRoot,
        bytes32 stateRoot,
        bytes[] calldata proof
    ) external pure override returns (bool) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(abi.encodePacked(account)));
        
        StorageValue[] memory proofs = MerklePatricia.VerifyEthereumProof(
            stateRoot, 
            proof, 
            keys
        );
        
        require(proofs.length == 1, "Invalid proof result length");
        require(proofs[0].value.length > 0, "Account does not exist");
        
        RLPReader.RLPItem[] memory accountData = proofs[0].value.toRlpItem().toList();
        require(accountData.length == 4, "Invalid account RLP data");
        
        require(accountData[0].toUint() == nonce, "Nonce mismatch");
        require(accountData[1].toUint() == balance, "Balance mismatch");
        require(bytes32(accountData[2].toUint()) == accountStateRoot, "Storage root mismatch");
        
        return true;
    }
}
