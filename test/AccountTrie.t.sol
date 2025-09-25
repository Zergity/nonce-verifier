// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AccountTrie.sol";
import "./data/AccountProofTestData.sol";

contract AccountTrieTest is Test {
    using AccountTrie for *;

    function testVerifyAccount() public pure {
        AccountProofTestData.BlockState memory blockState = AccountProofTestData.getBlock();
        AccountProofTestData.AccountState memory account = AccountProofTestData.getAccount();
        bytes[] memory proof = AccountProofTestData.getProof();
        
        bytes memory accountRLP = AccountTrie.verify(
            account.account,
            blockState.stateRoot,
            proof
        );
        
        (
            uint256 nonce,
            uint256 balance,
            bytes32 storageRoot,
            bytes32 codeHash
        ) = AccountTrie.decode(accountRLP);

        assertEq(nonce, account.nonce, "Nonce mismatch");
        assertEq(balance, account.balance, "Balance mismatch");
        assertEq(storageRoot, account.storageRoot, "Storage root mismatch");
        assertEq(codeHash, account.codeHash, "Code hash mismatch");
    }
}