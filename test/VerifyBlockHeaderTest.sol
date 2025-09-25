//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/AccountTrie.sol";
import "forge-std/Test.sol";

contract VerifyBlockHeaderTest is Test {
    function testHeaderRLP() public {
        bytes memory header = hex"f90215a022acefd40ca2e8d34f7b8b1597b00a92e1ccddbeec7ef8a1a7003637426eef38a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944838b106fce9647bdf1e7877bf73ce8b0bad5f97a0fa62252d9df2e93d494809a665f9395f12d10e8098a8e4319e78d283e5c07c0aa07dfc77a2f0ce1da1134331674c48646af4fe7c2cda4fe6520b470f90f20a23c8a00e91dfd95675015c2d61621196db69d8e1139df3a0516fc50c39a6de96a4f5a7b901007ffee7af3f735b76facf5f2fe727d5bb7193856db4d732704e9341fabe57a7b7efded3d5b3fc13247ab43fbfd78f9d19f78de8eccc6fbaff36fbb7eba7b660fff703b628f7f19f3efb7b7fea9c7ca7eb2beeb7b7a5ee7c393ff79fef86f8018dff3feb6cb37eebfea8f7fcabec78edef1a7f6727af5e767c9af47cb4b57fe3fb9f73b63bffefd33bfdd9eeef5637f743c09dcded6dfff3bdffe66ff6f4bafffb7fbfed8fd1fbeb3bdc717ef6b9e78da2f9f4fbee9ffff96eaaffde7ef68aa7f1febe5d6ff7ffbefe39f3fcf7c1b8bbfdedfd4e7e779f5753beedb103dd7f6bcfb2ff7ffe793fb59193ee55ecee6fcee7dd63ff31f7ffacf99bfdd31ea37f18e200840165a1de8402adf9988401b1d9048468d4cab798546974616e2028746974616e6275696c6465722e78797a29a027b28d1afe68f2eea1078a7723a033f500e74554e6141d7a12a79f6691754c14880000000000000000";
        bytes32 stateRoot = bytes32(uint(0xfa62252d9df2e93d494809a665f9395f12d10e8098a8e4319e78d283e5c07c0a));
        uint timestamp = 0x68d4cab7;

        // Test header RLP decoding
        (bytes32 decodedRoot, uint decodedTimestamp) = AccountTrie.extractFromBlockHeader(header);
        emit log_bytes32(decodedRoot);
        emit log_uint(decodedTimestamp);
        assertEq(decodedRoot, stateRoot, "state root mismatch");
        assertEq(decodedTimestamp, timestamp, "timestamp mismatch");
    }
}