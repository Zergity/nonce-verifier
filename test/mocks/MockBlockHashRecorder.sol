// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IBlockHashRecorder} from "../../src/IBlockHashRecorder.sol";

contract MockBlockHashRecorder is IBlockHashRecorder {
    mapping(uint256 => bytes32) private hashes;

    function blockHash(uint256 blockNumber) external view returns (bytes32) {
        return hashes[blockNumber];
    }

    function setBlockHash(uint256 blockNumber, bytes32 hash) external {
        hashes[blockNumber] = hash;
    }
}