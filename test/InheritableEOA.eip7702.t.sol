// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {InheritableEOA} from "../src/InheritableEOA.sol";
import {MockBlockHashRecorder} from "./mocks/MockBlockHashRecorder.sol";
import {BareAccount} from "../lib/account-abstraction/contracts/core/BareAccount.sol";

/**
 * @title InheritableEOA Real EIP-7702 Tests
 * @dev Tests InheritableEOA with real EIP-7702 delegation transactions
 * @notice These tests use Foundry's vm.signAndAttachDelegation() for authentic EIP-7702 behavior
 */
contract InheritableEOARealEIP7702Test is Test {
    InheritableEOA delegate;
    MockBlockHashRecorder mockRecorder;
    
    // Test accounts
    uint256 constant EOA_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address eoaAddress;
    address inheritor = address(0x123);
    uint32 testDelay = 86400; // 1 day

    function setUp() public {
        // Setup EOA address from private key
        eoaAddress = vm.addr(EOA_PRIVATE_KEY);
        
        // Deploy contracts
        delegate = new InheritableEOA();
        mockRecorder = new MockBlockHashRecorder();
        
        // Fund the EOA
        vm.deal(eoaAddress, 10 ether);
        
        console.log("EOA Address:", eoaAddress);
        console.log("Delegate Address:", address(delegate));
    }

    function testRealEIP7702BasicDelegation() public {
        // Before delegation - EOA should have no code
        assertEq(eoaAddress.code.length, 0, "EOA should have no code initially");
        
        // Sign and attach real EIP-7702 delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // After delegation - EOA should have delegation prefix + delegate address
        bytes memory expectedCode = abi.encodePacked(hex"ef0100", address(delegate));
        assertEq(eoaAddress.code, expectedCode, "EOA should have delegation code");
        
        console.log("EOA code after delegation:", vm.toString(eoaAddress.code));
    }

    function testRealEIP7702Configuration() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Now the EOA can call setConfig as if it's the contract itself
        // In EIP-7702, when the EOA calls a function, msg.sender is the EOA address
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Verify configuration was set (reading from the EOA's storage via delegation)
        assertEq(InheritableEOA(eoaAddress).getInheritor(), inheritor, "Inheritor should be set");
        assertEq(InheritableEOA(eoaAddress).getDelay(), testDelay, "Delay should be set");
        assertEq(address(InheritableEOA(eoaAddress).getBlockHashRecorder()), address(mockRecorder), "Recorder should be set");
        assertFalse(InheritableEOA(eoaAddress).getIsClaimed(), "Should not be claimed initially");
    }

    function testRealEIP7702ConfigurationEvents() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Expect the ConfigSet event
        vm.expectEmit(true, true, true, true);
        emit InheritableEOA.ConfigSet(inheritor, testDelay, address(mockRecorder));
        
        // Configure through the delegated EOA
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
    }

    function testRealEIP7702UnauthorizedAccess() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Try to call from a different address (should fail)
        address unauthorized = address(0x999);
        vm.prank(unauthorized);
        vm.expectRevert(BareAccount.Unauthorized.selector);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
    }

    function testRealEIP7702DirectDelegateAccess() public {
        // Attach delegation to EOA
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Direct access to delegate contract should still require proper authorization
        // The delegate contract itself still enforces its own access control
        vm.prank(address(0x999));
        vm.expectRevert(BareAccount.Unauthorized.selector);
        delegate.setConfig(inheritor, testDelay, address(mockRecorder));
    }

    function testRealEIP7702ConfigurationUpdate() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Initial configuration
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Update configuration
        address newInheritor = address(0x456);
        uint32 newDelay = 172800; // 2 days
        MockBlockHashRecorder newRecorder = new MockBlockHashRecorder();
        
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(newInheritor, newDelay, address(newRecorder));
        
        // Verify updates (reading from EOA's storage)
        assertEq(InheritableEOA(eoaAddress).getInheritor(), newInheritor, "Inheritor should be updated");
        assertEq(InheritableEOA(eoaAddress).getDelay(), newDelay, "Delay should be updated");
        assertEq(address(InheritableEOA(eoaAddress).getBlockHashRecorder()), address(newRecorder), "Recorder should be updated");
    }

    function testRealEIP7702ExecutePermissions() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Configure the delegated EOA
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Test execution permissions
        bytes memory callData = abi.encodeWithSignature("nonExistentFunction()");
        
        // EOA should be able to execute (but call will fail due to non-existent function)
        vm.prank(eoaAddress);
        (bool success,) = eoaAddress.call(callData);
        assertFalse(success, "Call should fail due to non-existent function, not authorization");
        
        // Inheritor should not be able to execute (not claimed yet)
        vm.prank(inheritor);
        vm.expectRevert(BareAccount.Unauthorized.selector);
        InheritableEOA(eoaAddress).execute(address(0), 0, "");
    }

    function testRealEIP7702MultipleEOAs() public {
        // Create second EOA
        uint256 secondPrivateKey = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;
        address secondEoa = vm.addr(secondPrivateKey);
        vm.deal(secondEoa, 10 ether);
        
        // Create second delegate contract
        InheritableEOA secondDelegate = new InheritableEOA();
        
        // Attach different delegates to different EOAs
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        vm.signAndAttachDelegation(address(secondDelegate), secondPrivateKey);
        
        // Configure both EOAs independently
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        address secondInheritor = address(0x789);
        vm.prank(secondEoa);
        InheritableEOA(secondEoa).setConfig(secondInheritor, testDelay * 2, address(mockRecorder));
        
        // Verify independent configurations (each EOA has its own storage)
        assertEq(InheritableEOA(eoaAddress).getInheritor(), inheritor, "First EOA inheritor");
        assertEq(InheritableEOA(secondEoa).getInheritor(), secondInheritor, "Second EOA inheritor");
        assertEq(InheritableEOA(eoaAddress).getDelay(), testDelay, "First EOA delay");
        assertEq(InheritableEOA(secondEoa).getDelay(), testDelay * 2, "Second EOA delay");
    }

    function testRealEIP7702GetterFunctions() public {
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // Configure the delegated EOA
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Test all getter functions work through the delegated EOA
        assertEq(InheritableEOA(eoaAddress).getInheritor(), inheritor, "getInheritor should work");
        assertEq(InheritableEOA(eoaAddress).getDelay(), testDelay, "getDelay should work");
        assertEq(address(InheritableEOA(eoaAddress).getBlockHashRecorder()), address(mockRecorder), "getBlockHashRecorder should work");
        assertFalse(InheritableEOA(eoaAddress).getIsClaimed(), "getIsClaimed should work");
    }

    function testRealEIP7702CodeIntrospection() public {
        // Before delegation
        assertTrue(eoaAddress.code.length == 0, "EOA should have no code initially");
        
        // Attach delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        
        // After delegation - should have EIP-7702 format: 0xef0100 + delegate_address
        bytes memory eoaCode = eoaAddress.code;
        assertTrue(eoaCode.length == 23, "EOA should have 23 bytes of code (3 prefix + 20 address)");
        
        // Check prefix
        assertEq(uint8(eoaCode[0]), 0xef, "First byte should be 0xef");
        assertEq(uint8(eoaCode[1]), 0x01, "Second byte should be 0x01");
        assertEq(uint8(eoaCode[2]), 0x00, "Third byte should be 0x00");
        
        // Extract delegate address from code
        address extractedDelegate;
        assembly {
            extractedDelegate := mload(add(eoaCode, 0x17)) // Skip 3 prefix bytes + 12 padding bytes
        }
        assertEq(extractedDelegate, address(delegate), "Extracted delegate address should match");
    }

    function testRealEIP7702StateIsolation() public {
        // Create two different delegate contracts
        InheritableEOA delegate1 = new InheritableEOA();
        InheritableEOA delegate2 = new InheritableEOA();
        
        // Attach first delegate
        vm.signAndAttachDelegation(address(delegate1), EOA_PRIVATE_KEY);
        
        // Configure through first delegate
        vm.prank(eoaAddress);
        InheritableEOA(eoaAddress).setConfig(inheritor, testDelay, address(mockRecorder));
        
        // Switch to second delegate
        vm.signAndAttachDelegation(address(delegate2), EOA_PRIVATE_KEY);
        
        // State should be isolated - delegate2 should have default values
        assertEq(delegate2.getInheritor(), address(0), "Second delegate should have zero inheritor");
        assertEq(delegate2.getDelay(), 0, "Second delegate should have zero delay");
        
        // EOA retains its own storage even when switching delegates
        assertEq(InheritableEOA(eoaAddress).getInheritor(), inheritor, "EOA should retain its state");
        
        // But delegate1 should have default values (unchanged)
        assertEq(delegate1.getInheritor(), address(0), "First delegate should have default state");
    }

    // Helper function to test edge cases
    function testRealEIP7702EdgeCases() public {
        // Test delegation with zero address - delegation succeeds but subsequent calls return empty
        vm.signAndAttachDelegation(address(0), EOA_PRIVATE_KEY);
        
        // Use low-level call to test zero delegation behavior
        (bool success, bytes memory data) = eoaAddress.staticcall(
            abi.encodeWithSelector(InheritableEOA.getInheritor.selector)
        );
        assertTrue(success, "Call should succeed");
        assertEq(data.length, 0, "Should return empty data for zero delegation");
        
        // Test that we can recover by creating a proper delegation
        vm.signAndAttachDelegation(address(delegate), EOA_PRIVATE_KEY);
        address inheritedAddress = InheritableEOA(eoaAddress).getInheritor();
        assertEq(inheritedAddress, address(0), "Should still be uninitialized after proper delegation");
    }
}