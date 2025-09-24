// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AccountVerifier.sol";

contract AccountVerifierTest is Test {
    AccountVerifier public verifier;

    function setUp() public {
        verifier = new AccountVerifier();
    }

    function testVerifyAccount() public {
        // Test data from mainnet account 0x28c6c06298d514db089934071355e5743bf21d60
        address account = 0x28c6c06298d514db089934071355e5743bf21d60;
        uint256 nonce = 13673493;
        uint256 balance = 68580155222660410366423;
        bytes32 storageRoot = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;
        bytes32 stateRoot = 0x816d6321c1dbe52f70002beed7f4441902b062510100d69c7d0488de85b8b355;
        
        // TODO: Add real proof from eth_getProof call
        bytes32[] memory proof = new bytes32[](0);
        
        bool result = verifier.verifyAccount(
            account,
            nonce,
            balance,
            storageRoot,
            stateRoot,
            proof
        );
        
        // TODO: Add assertion once proof is added
        // assertTrue(result);
    }
}