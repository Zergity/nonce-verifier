import fetch from 'node-fetch';
import { ethers } from 'ethers';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { encode } from 'rlp';

const TEST_ACCOUNT = '0x28c6c06298d514db089934071355e5743bf21d60'; // Binance 14 Hot Wallet

async function fetchRPC(method, params) {
    const response = await fetch('https://eth.meowrpc.com', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params,
        }),
    });
    const json = await response.json();
    if (json.error) throw new Error(json.error.message);
    return json.result;
}

async function main() {
    // Get latest block number in hex
    const blockNumber = parseInt(await fetchRPC('eth_blockNumber', []));
    const blockHex = '0x' + blockNumber.toString(16);
    
    console.log('Fetching data for:');
    console.log('Block:', blockNumber);
    console.log('Account:', TEST_ACCOUNT);
    
    // Get block data with full header fields
    const block = await fetchRPC('eth_getBlockByNumber', [blockHex, true]);
    const stateRoot = block.stateRoot;
    console.log('\nBlock State Root:', stateRoot);
    
    // Extract block header fields (in the correct order for RLP encoding)
    const headerFields = [
        block.parentHash,
        block.sha3Uncles,
        block.miner,
        block.stateRoot,
        block.transactionsRoot,
        block.receiptsRoot,
        block.logsBloom,
        ethers.BigNumber.from(block.difficulty).toHexString(),
        ethers.BigNumber.from(block.number).toHexString(),
        ethers.BigNumber.from(block.gasLimit).toHexString(),
        ethers.BigNumber.from(block.gasUsed).toHexString(),
        ethers.BigNumber.from(block.timestamp).toHexString(),
        block.extraData,
        block.mixHash,
        block.nonce
    ].map(hex => ethers.utils.arrayify(hex));

    // RLP encode block header
    const blockHeaderRLP = ethers.utils.hexlify(encode(headerFields));
    console.log('\nBlock Header RLP:', blockHeaderRLP);

    // Verify that the header hash matches
    const headerHash = ethers.utils.keccak256(blockHeaderRLP);
    console.log('\nComputed Block Hash:', headerHash);
    console.log('Actual Block Hash:', block.hash);

    // Get account proof using eth_getProof
    const proof = await fetchRPC('eth_getProof', [
        TEST_ACCOUNT,
        [],
        blockHex
    ]);
    
    console.log('\nAccount State:');
    console.log('Nonce:', parseInt(proof.nonce));
    console.log('Balance:', ethers.BigNumber.from(proof.balance).toString());
    console.log('Storage Root:', proof.storageHash);
    console.log('Code Hash:', proof.codeHash);
    
    // Save test data
    const testData = {
        block: {
            number: blockNumber,
            hash: block.hash,
            stateRoot: block.stateRoot,
            headerRLP: blockHeaderRLP
        },
        account: {
            address: TEST_ACCOUNT,
            nonce: parseInt(proof.nonce),
            balance: ethers.BigNumber.from(proof.balance).toString(),
            storageRoot: proof.storageHash,
            codeHash: proof.codeHash
        },
        proof: proof.accountProof
    };

    // Create test data directory if it doesn't exist
    await mkdir('test/data', { recursive: true });

    // Save as Solidity test data
    const solidityTest = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library AccountProofTestData {
    struct AccountState {
        address account;
        uint256 nonce;
        uint256 balance;
        bytes32 storageRoot;
        bytes32 codeHash;
    }

    struct BlockState {
        uint256 number;
        bytes32 hash;
        bytes32 stateRoot;
    }

    function getBlock() internal pure returns (BlockState memory) {
        return BlockState({
            number: ${blockNumber},
            hash: ${block.hash},
            stateRoot: ${stateRoot}
        });
    }

    function getAccount() internal pure returns (AccountState memory) {
        return AccountState({
            account: ${TEST_ACCOUNT},
            nonce: ${parseInt(proof.nonce)},
            balance: ${ethers.BigNumber.from(proof.balance).toString()},
            storageRoot: ${proof.storageHash},
            codeHash: ${proof.codeHash}
        });
    }

    function getProof() internal pure returns (bytes[] memory) {
        bytes[] memory proof = new bytes[](${proof.accountProof.length});
        ${proof.accountProof.map((node, i) => `proof[${i}] = hex"${node.slice(2)}";`).join('\n        ')}
        return proof;
    }
}`;

    // Write test data files
    await writeFile('test/data/AccountProofTestData.sol', solidityTest);
    await writeFile('test/data/account-proof.json', JSON.stringify(testData, null, 2));
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });