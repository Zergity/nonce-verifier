// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        // AccountTrie is a library and doesn't need deployment
        // Add deployment logic for actual contracts when they exist
        vm.stopBroadcast();
    }
}