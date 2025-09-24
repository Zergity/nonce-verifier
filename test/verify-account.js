import fetch from 'node-fetch';
import { ethers } from 'ethers';
import { readFile } from 'fs/promises';

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
    
    // Get block data
    const block = await fetchRPC('eth_getBlockByNumber', [blockHex, false]);
    const stateRoot = block.stateRoot;
    console.log('\nBlock State Root:', stateRoot);
    
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
    
    console.log('\nAccount Proof:');
    console.log('Length:', proof.accountProof.length);
    
    // Analyze proof structure
    console.log('\nProof Analysis:');
    proof.accountProof.forEach((node, i) => {
        const nodeBytes = ethers.utils.arrayify(node);
        console.log(`\nNode ${i}:`);
        console.log('Size:', nodeBytes.length, 'bytes');
        
        // First byte indicates RLP structure
        const firstByte = nodeBytes[0];
        if (firstByte >= 0xf8) {
            // Long list
            const sizeBytes = firstByte - 0xf7;
            const contentStart = 1 + sizeBytes;
            console.log('Type: Long list');
            console.log('Content size bytes:', sizeBytes);
            console.log('Content starts at:', contentStart);
        } else if (firstByte >= 0xc0) {
            // Short list
            console.log('Type: Short list');
            console.log('Content size:', firstByte - 0xc0);
        } else if (firstByte >= 0xb8) {
            // Long string
            const sizeBytes = firstByte - 0xb7;
            const contentStart = 1 + sizeBytes;
            console.log('Type: Long string');
            console.log('Size bytes:', sizeBytes);
            console.log('Content starts at:', contentStart);
        } else if (firstByte >= 0x80) {
            // Short string
            console.log('Type: Short string');
            console.log('Size:', firstByte - 0x80);
        } else {
            console.log('Type: Single byte');
        }
    });
    
    // Verify the final proof node contains account data
    const lastNode = proof.accountProof[proof.accountProof.length - 1];
    const lastNodeBytes = ethers.utils.arrayify(lastNode);
    
    console.log('\nAccount Leaf Node Analysis:');
    // The last node should be a list containing [path, [nonce, balance, storageRoot, codeHash]]
    console.log('Raw:', lastNode);
    
    // Compare state root to the block
    console.log('\nState Root Verification:');
    console.log('Block State Root:', stateRoot);
    console.log('First Proof Node:', proof.accountProof[0]);
    console.log('State roots match:', stateRoot === proof.accountProof[0].slice(0, 66));
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });