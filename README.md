# Account Verifier

AccountVerifier is a Solidity contract designed to verify an account's state (nonce, balance, storage root, and code hash) against Ethereum's state root using a Merkle proof. This enables trustless verification of account states using eth_getProof data.

## Project Structure

- **src/**: Contains the main contract files.
  - **AccountVerifier.sol**: Implementation of the `AccountVerifier` contract with RLP decoding.
  
- **lib/**: Contains external libraries.
  - **forge-std/**: Standard library for Foundry.
  - **solidity-merkle-trees/**: Library for MPT and RLP operations.

- **script/**: Contains deployment scripts.
  - **Deploy.s.sol**: Script for deploying the `AccountVerifier` contract.

- **test/**: Contains test files for the project.
  - **AccountVerifier.t.sol**: Solidity test cases for the contract.
  - **verify-account.js**: JavaScript test for fetching and verifying real account proofs.

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd nonce-verifier
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables in the `.env` file.

4. Deploy the contract using Foundry:
   ```bash
   forge script script/Deploy.s.sol
   ```

## Usage

After deployment, the `NonceVerifier` contract can be interacted with to verify account information against the provided state root and Merkle proof. Refer to the contract documentation for specific function usage.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.