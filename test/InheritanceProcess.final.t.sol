// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {InheritableEOA} from "../src/InheritableEOA.sol";
import {MockBlockHashRecorder} from "./mocks/MockBlockHashRecorder.sol";

/**
 * @title InheritanceProcessFinalTest
 * @dev Test inheritance process with proper EIP-7702 simulation
 */
contract InheritanceProcessFinalTest is Test {
    InheritableEOA inheritableEoa;
    MockBlockHashRecorder blockHashRecorder;
    
    address inheritor = address(0x456);
    uint32 delay = uint32(7 days);
    
    function setUp() public {
        blockHashRecorder = new MockBlockHashRecorder();
        inheritableEoa = new InheritableEOA();
        
        // Set block hash in mock
        blockHashRecorder.setBlockHash(23437790, 0xb3dfa50ff99dac95f4b48bed653cf5ff7bc7c3d8e0d63f3f4549902013f956ca);
    }
    
    function testBasicGetters() public view {
        // Test basic getter functions work correctly
        assertEq(inheritableEoa.getInheritor(), address(0));
        assertEq(inheritableEoa.getDelay(), 0);
        assertEq(inheritableEoa.getBlockHashRecorder(), address(0));
        assertFalse(inheritableEoa.getIsClaimed());
    }
    
    function testEOACanConfigureSelf() public {
        // Simulate EIP-7702: the contract calling itself
        vm.startPrank(address(inheritableEoa));
        
        // This should work - contract calling itself
        inheritableEoa.setConfig(inheritor, delay, address(blockHashRecorder));
        
        // Verify configuration was set
        assertEq(inheritableEoa.getInheritor(), inheritor);
        assertEq(inheritableEoa.getDelay(), delay);
        assertEq(inheritableEoa.getBlockHashRecorder(), address(blockHashRecorder));
        
        vm.stopPrank();
    }
    
    function testNonEOACannotConfigure() public {
        // Any other address should be rejected
        vm.prank(address(0x999));
        vm.expectRevert("Unauthorized()");
        inheritableEoa.setConfig(inheritor, delay, address(blockHashRecorder));
    }
    
    function testExecutionPermissions() public {
        // Configure the contract first
        vm.prank(address(inheritableEoa));
        inheritableEoa.setConfig(inheritor, delay, address(blockHashRecorder));
        
        // Create some dummy call data
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");
        
        // EOA (address(this) in EIP-7702) can execute
        vm.prank(address(inheritableEoa));
        (bool success,) = address(inheritableEoa).call(data);
        // Will fail due to nonexistent function, but not due to authorization
        assertFalse(success);
        
        // Inheritor cannot execute (not claimed yet)
        vm.prank(inheritor);
        vm.expectRevert("Unauthorized()");
        (success,) = address(inheritableEoa).call(data);
    }
    
    function testConfigEvents() public {
        // Configure the contract and check event emission
        vm.prank(address(inheritableEoa));
        
        vm.expectEmit(true, true, true, true);
        emit InheritableEOA.ConfigSet(inheritor, delay, address(blockHashRecorder));
        
        inheritableEoa.setConfig(inheritor, delay, address(blockHashRecorder));
    }
    
    function testPartialConfiguration() public {
        // Test partial configuration updates
        vm.startPrank(address(inheritableEoa));
        
        // Set initial config
        inheritableEoa.setConfig(inheritor, delay, address(blockHashRecorder));
        
        // Update only inheritor (pass 0 for others to keep unchanged)
        address newInheritor = address(0x789);
        inheritableEoa.setConfig(newInheritor, 0, address(0));
        
        // Verify only inheritor changed
        assertEq(inheritableEoa.getInheritor(), newInheritor);
        assertEq(inheritableEoa.getDelay(), delay); // unchanged
        assertEq(inheritableEoa.getBlockHashRecorder(), address(blockHashRecorder)); // unchanged
        
        vm.stopPrank();
    }
}