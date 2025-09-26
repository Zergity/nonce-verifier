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
    address internal s_blockHashRecorder;

    // Storage variables that can only be changed by the EOA (address(this) in EIP-7702 context)
    address internal s_inheritor;
    uint32 internal s_delay; // Delay in seconds
    bool internal s_claimed;

    uint64 internal s_nonce; // Unused storage
    uint64 internal s_timestamp; // Unused storage

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
    event ConfigSet(address indexed inheritor, uint32 delay, address blockHashRecorder);
    event NonceRecorded(uint64 nonce, uint64 timestamp);
    event InheritanceClaimed();

    /**
     * @dev Internal function to check execution permissions
     *      Overrides the base BareAccount logic to add inheritance support
     */
    function _requireForExecute() internal view override {
        if (msg.sender == address(this)) {
            return;
        }
        // Allow claimed inheritor to execute
        require(s_claimed && msg.sender == s_inheritor, Unauthorized());
    }

    /**
     * @dev Record nonce and timestamp for inheritance claim
     * @param account The EOA account address (should be address(this) in EIP-7702 context)
     * @param blockHeaderRLP RLP encoded block header
     * @param proof Merkle proof for account state in block
     */
    function record(
        bytes memory blockHeaderRLP,
        bytes[] memory proof
    ) public {
        // Verify block and get nonce + timestamp
        (uint256 nonce, uint256 timestamp) = AccountTrie.verifyNonceTime(
            address(this),
            blockHeaderRLP,
            proof,
            s_blockHashRecorder
        );

        // Check if we should update stored values
        if (nonce < s_nonce) {
            revert("nonce smaller");
        }
        if (nonce == s_nonce && timestamp >= s_timestamp) {
            revert("timestamp not newer");
        }
        s_nonce = uint64(nonce);
        s_timestamp = uint64(timestamp);
        
        emit NonceRecorded(s_nonce, s_timestamp);
    }

    /**
     * @dev Claim inheritance by proving nonce hasn't changed over the delay period
     * @param account The EOA account address (should be address(this) in EIP-7702 context)
     * @param blockHeaderRLP RLP encoded recent block header
     * @param proof Merkle proof for account state in recent block
     */
    function claim(
        bytes memory blockHeaderRLP,
        bytes[] memory proof
    ) public {
        require(s_inheritor != address(0), InvalidInheritor());
        require(s_delay > 0, InvalidDelay());
        require(!s_claimed, "claimed");
        require(s_nonce > 0, "!nonce");

        // Verify new block and get nonce + timestamp
        (uint256 nonce, uint256 timestamp) = AccountTrie.verifyNonceTime(
            address(this),
            blockHeaderRLP,
            proof,
            s_blockHashRecorder
        );

        // Check that enough time has passed
        require(timestamp >= s_timestamp + s_delay, InheritanceNotReady());

        // Check that nonce hasn't changed (account hasn't been used)
        require(nonce == s_nonce, NonceChanged());

        // Mark inheritance as claimed and clear stored values
        s_claimed = true;
        delete s_nonce;
        delete s_timestamp;
        
        emit InheritanceClaimed();
    }

    /**
     * @dev Convenience function to record and claim inheritance in one transaction
     * @param account The EOA account address (should be address(this) in EIP-7702 context)
     * @param oldBlockHeaderRLP RLP encoded block header from delay period ago
     * @param oldProof Merkle proof for account state in old block
     * @param newBlockHeaderRLP RLP encoded recent block header
     * @param newProof Merkle proof for account state in new block
     */
    function recordAndClaim(
        bytes memory oldBlockHeaderRLP,
        bytes[] memory oldProof,
        bytes memory newBlockHeaderRLP,
        bytes[] memory newProof
    ) public {
        record(oldBlockHeaderRLP, oldProof);
        claim(newBlockHeaderRLP, newProof);
    }

    // ============ SETTERS & GETTERS ============

    /**
     * @dev Set the inheritor, delay, and block hash recorder configuration. Can only be called by the EOA (address(this) in EIP-7702)
     * @param inheritor Address that can inherit the account after delay (ignored if zero)
     * @param delay Time in seconds that must pass with unchanged nonce before inheritance (ignored if zero)
     * @param blockHashRecorder Address of the block hash recorder contract (ignored if zero)
     */
    function setConfig(address inheritor, uint32 delay, address blockHashRecorder) public onlyEOA {
        if (inheritor != address(0)) {
            s_inheritor = inheritor;
        }
        
        if (delay > 0) {
            s_delay = delay;
        }
        
        if (blockHashRecorder != address(0)) {
            s_blockHashRecorder = blockHashRecorder;
        }
        
        emit ConfigSet(s_inheritor, s_delay, s_blockHashRecorder);
    }

    /**
     * @dev Get the block hash recorder address
     * @return The address of the block hash recorder
     */
    function blockHashRecorder() public view returns (address) {
        return s_blockHashRecorder;
    }

    /**
     * @dev Get the inheritor address
     * @return The address of the inheritor
     */
    function inheritor() public view returns (address) {
        return s_inheritor;
    }

    /**
     * @dev Get the inheritance delay
     * @return The delay in seconds
     */
    function delay() public view returns (uint256) {
        return s_delay;
    }

    /**
     * @dev Get the claimed status
     * @return True if inheritance has been claimed
     */
    function isClaimed() public view returns (bool) {
        return s_claimed;
    }
}