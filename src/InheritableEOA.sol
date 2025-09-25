// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AccountTrie.sol";
import "./IBlockHashRecorder.sol";
import "../lib/account-abstraction/contracts/core/BareAccount.sol";

/* solhint-disable avoid-low-level-calls */

/**
 * @title InheritableEOA
 * @dev A contract designed to be delegated to by EOA using EIP-7702 transaction.
 *      Implements inheritance logic where an inheritor can assume full access to the account
 *      after proving the account nonce hasn't changed over a specified delay period.
 */
contract InheritableEOA is BareAccount {
    using AccountTrie for *;

    // Block hash recorder for verifying historical block data
    address private s_blockHashRecorder;

    // Storage variables that can only be changed by the EOA (address(this) in EIP-7702 context)
    address private s_inheritor;
    uint256 private s_delay; // Delay in seconds

    // Custom errors
    error InvalidInheritor();
    error InvalidDelay();
    error InheritanceNotReady();
    error NonceChanged();

    // Modifier for EOA authorization
    modifier onlyEOA() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    // Events
    event InheritorSet(address indexed inheritor);
    event DelaySet(uint256 delay);
    event InheritanceExecuted(address indexed inheritor, address indexed account);

    /**
     * @dev Constructor sets the block hash recorder
     * @param blockHashRecorder Address of the block hash recorder contract
     */
    constructor(address blockHashRecorder) {
        require(blockHashRecorder != address(0), "Invalid block hash recorder");
        s_blockHashRecorder = blockHashRecorder;
    }

    /**
     * @dev Set the inheritor address. Can only be called by the EOA (address(this) in EIP-7702)
     * @param inheritor Address that can inherit the account after delay
     */
    function setInheritor(address inheritor) external onlyEOA {
        require(inheritor != address(0), InvalidInheritor());
        
        s_inheritor = inheritor;
        emit InheritorSet(inheritor);
    }

    /**
     * @dev Set the inheritance delay. Can only be called by the EOA (address(this) in EIP-7702)
     * @param delay Time in seconds that must pass with unchanged nonce before inheritance
     */
    function setDelay(uint256 delay) external onlyEOA {
        require(delay > 0, InvalidDelay());
        
        s_delay = delay;
        emit DelaySet(delay);
    }

    /**
     * @dev Get the block hash recorder address
     * @return The address of the block hash recorder
     */
    function getBlockHashRecorder() external view returns (address) {
        return s_blockHashRecorder;
    }

    /**
     * @dev Get the inheritor address
     * @return The address of the inheritor
     */
    function getInheritor() external view returns (address) {
        return s_inheritor;
    }

    /**
     * @dev Get the inheritance delay
     * @return The delay in seconds
     */
    function getDelay() external view returns (uint256) {
        return s_delay;
    }

    /**
     * @dev Execute a single call from the account
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Call data
     */
    function execute(address target, uint256 value, bytes calldata data) external override {
        _requireForExecute();
        
        (bool success, bytes memory returnData) = target.call{value: value, gas: gasleft()}(data);
        if (!success) {
            // Revert with the original error data
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }
    }

    /**
     * @dev Execute inheritance by proving nonce hasn't changed over the delay period
     * @param account The EOA account address (should be address(this) in EIP-7702 context)
     * @param oldBlockHeaderRLP RLP encoded block header from delay period ago
     * @param oldProof Merkle proof for account state in old block
     * @param newBlockHeaderRLP RLP encoded recent block header
     * @param newProof Merkle proof for account state in new block
     * @param target Target contract address to execute
     * @param value ETH value to send
     * @param data Call data
     */
    function executeInheritance(
        address account,
        bytes memory oldBlockHeaderRLP,
        bytes[] memory oldProof,
        bytes memory newBlockHeaderRLP,
        bytes[] memory newProof,
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        require(s_inheritor != address(0), InvalidInheritor());
        require(s_delay > 0, InvalidDelay());
        require(msg.sender == s_inheritor, Unauthorized());
        require(account == address(this), "Invalid account");

        // Verify old block and get nonce + timestamp
        (uint256 oldNonce, uint256 oldTimestamp) = AccountTrie.verifyNonceTime(
            account,
            oldBlockHeaderRLP,
            oldProof,
            s_blockHashRecorder
        );

        // Verify new block and get nonce + timestamp
        (uint256 newNonce, uint256 newTimestamp) = AccountTrie.verifyNonceTime(
            account,
            newBlockHeaderRLP,
            newProof,
            s_blockHashRecorder
        );

        // Check that enough time has passed
        require(newTimestamp >= oldTimestamp + s_delay, InheritanceNotReady());

        // Check that nonce hasn't changed (account hasn't been used)
        require(oldNonce == newNonce, NonceChanged());

        // Execute the transaction as the inheritor now has full access
        emit InheritanceExecuted(s_inheritor, account);
        
        (bool success, bytes memory returnData) = target.call{value: value, gas: gasleft()}(data);
        if (!success) {
            // Revert with the original error data
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }
    }

    /**
     * @dev Internal function to check execution permissions
     *      Overrides the base BareAccount logic to add inheritance support
     */
    function _requireForExecute() internal view override {
        // Allow the original EOA (address(this) in EIP-7702 context) to execute
        if (msg.sender == address(this)) {
            return;
        }

        // For inheritance, caller must use executeInheritance function
        // This function should not be directly callable by inheritor
        revert Unauthorized();
    }
}