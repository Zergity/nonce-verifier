// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AccountVerifier.sol";
import "./data/AccountProofTestData.sol";

contract AccountVerifierTest is Test {
    AccountVerifier public verifier;

    function setUp() public {
        verifier = new AccountVerifier();
    }

    function testVerifyAccount() public view {
        AccountProofTestData.BlockState memory blockState = AccountProofTestData.getBlock();
        AccountProofTestData.AccountState memory account = AccountProofTestData.getAccount();
        bytes[] memory proof = AccountProofTestData.getProof();
        
        bool result = verifier.verifyAccount(
            account.account,
            account.nonce,
            account.balance,
            account.storageRoot,
            blockState.stateRoot,
            proof
        );
        
        assertTrue(result, "Account proof verification failed");
    }
}