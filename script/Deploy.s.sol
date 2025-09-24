// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/AccountVerifier.sol";

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        AccountVerifier verifier = new AccountVerifier();
        vm.stopBroadcast();
    }
}