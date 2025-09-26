// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {InheritableEOA} from "../src/InheritableEOA.sol";
import {MockBlockHashRecorder} from "./mocks/MockBlockHashRecorder.sol";
import {BareAccount} from "../lib/account-abstraction/contracts/core/BareAccount.sol";

contract InheritableEOABasicTest is Test {
    InheritableEOA inheritableEoa;
    MockBlockHashRecorder mockRecorder;
    address inheritor = address(0x123);
    uint32 testDelay = 86400; // 1 day

    function setUp() public {
        mockRecorder = new MockBlockHashRecorder();
        inheritableEoa = new InheritableEOA();
    }

    function testSetConfig() public {
        // Test setting config as EOA (address(this) context)
        vm.prank(address(inheritableEoa));
        inheritableEoa.setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Verify the values were set
        assertEq(inheritableEoa.getInheritor(), inheritor);
        assertEq(inheritableEoa.getDelay(), testDelay);
        assertEq(inheritableEoa.getBlockHashRecorder(), address(mockRecorder));
        assertFalse(inheritableEoa.getIsClaimed());
    }

    function testSetConfigPartial() public {
        // Test setting only some values (others should be ignored)
        vm.prank(address(inheritableEoa));
        inheritableEoa.setConfig(inheritor, 0, address(0));
        
        // Verify that only non-zero values were set
        assertEq(inheritableEoa.getInheritor(), inheritor);
        assertEq(inheritableEoa.getDelay(), 0);
        assertEq(inheritableEoa.getBlockHashRecorder(), address(0));
    }

    function testSetConfigUnauthorized() public {
        // Should revert when not called by address(this)
        vm.expectRevert(BareAccount.Unauthorized.selector);
        inheritableEoa.setConfig(inheritor, testDelay, address(mockRecorder));
    }

    function testExecutePermissions() public {
        // Set up config
        vm.prank(address(inheritableEoa));
        inheritableEoa.setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Should reject inheritor before claiming
        vm.expectRevert(BareAccount.Unauthorized.selector);
        vm.prank(inheritor);
        inheritableEoa.execute(address(0), 0, "");
        
        // Should reject random user
        vm.expectRevert(BareAccount.Unauthorized.selector);
        vm.prank(address(0x456));
        inheritableEoa.execute(address(0), 0, "");
    }
}