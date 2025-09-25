// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AccountTrie.sol";
import "./data/AccountProofTestData.sol";
import "./mocks/MockBlockHashRecorder.sol";

contract AccountTrieTest is Test {
    using AccountTrie for *;
    using MerklePatricia for *;

    function testBlockHeader() public {
        AccountProofTestData.BlockState memory blockState = AccountProofTestData.getBlock();

        (bytes32 stateRoot, uint256 timestamp) = AccountTrie.extractFromBlockHeader(blockState.headerRLP);
        assertEq(stateRoot, blockState.stateRoot, "state root mismatch");
        emit log_bytes32(stateRoot);
        emit log_uint(timestamp);
    }

    function testVerifyAccountState() public {
        AccountProofTestData.BlockState memory blockState = AccountProofTestData.getBlock();
        AccountProofTestData.AccountState memory account = AccountProofTestData.getAccount();
        bytes[] memory proof = AccountProofTestData.getProof();

        bytes memory rlpAccount = AccountTrie.verify(account.account, blockState.stateRoot, proof);
        require(rlpAccount.length > 0, "Account not found");

        // Parse account RLP fields
        (
            uint256 nonce,
            uint256 balance,
            bytes32 storageRoot,
            bytes32 codeHash
        ) = AccountTrie.decode(rlpAccount);

        // Verify each field matches test data
        assertEq(nonce, account.nonce, "nonce mismatch");
        assertEq(balance, account.balance, "balance mismatch");
        assertEq(storageRoot, account.storageRoot, "storageRoot mismatch");
        assertEq(codeHash, account.codeHash, "codeHash mismatch");
    }

    function tryVerify(address account, bytes32 stateRoot, bytes[] memory proof) public pure returns (bytes memory) {
        return AccountTrie.verify(account, stateRoot, proof);
    }

    function testVerifyNonceTime() public {
        AccountProofTestData.BlockState memory blockState = AccountProofTestData.getBlock();
        AccountProofTestData.AccountState memory account = AccountProofTestData.getAccount();
        bytes[] memory proof = AccountProofTestData.getProof();

        // Deploy mock BlockHashRecorder
        MockBlockHashRecorder mockRecorder = new MockBlockHashRecorder();
        mockRecorder.setBlockHash(blockState.number, blockState.hash);

        // Log block hashes for debugging
        bytes32 calculatedHash = keccak256(blockState.headerRLP);
        emit log_named_bytes32("Expected block hash", blockState.hash);
        emit log_named_bytes32("Calculated block hash", calculatedHash);

        // Verify account nonce and block timestamp
        (uint256 nonce, uint256 timestamp) = AccountTrie.verifyNonceTime(
            account.account,
            blockState.headerRLP,
            proof,
            address(mockRecorder)
        );

        assertEq(nonce, account.nonce, "nonce mismatch");
        assertEq(timestamp, blockState.timestamp, "timestamp mismatch");
    }
}