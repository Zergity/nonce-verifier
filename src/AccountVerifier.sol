// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solidity-merkle-trees/trie/ethereum/RLPReader.sol";

interface IAccountVerifier {
    function verifyAccount(
        address account,
        uint256 nonce,
        uint256 balance,
        bytes32 accountStateRoot,
        bytes32 stateRoot,
        bytes32[] calldata proof
    ) external view returns (bool);
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
        bytes32[] calldata proof
    ) external view override returns (bool) {
        bytes memory path = abi.encodePacked(keccak256(abi.encodePacked(account)));
        bytes memory node = abi.encodePacked(proof[0]);
        RLPReader.RLPItem[] memory accountData = node.toRlpItem().toList();
        
        require(accountData.length == 4, "Invalid account RLP data");
        
        uint256 actualNonce = accountData[0].toUint();
        uint256 actualBalance = accountData[1].toUint();
        bytes32 actualStateRoot = bytes32(accountData[2].toUint());
        
        require(nonce == actualNonce, "Nonce mismatch");
        require(balance == actualBalance, "Balance mismatch");
        require(accountStateRoot == actualStateRoot, "State root mismatch");
        
        // TODO: Implement full MPT verification
        require(keccak256(node) == stateRoot, "Invalid state root");
        
        return true;
        return true;
    }
}