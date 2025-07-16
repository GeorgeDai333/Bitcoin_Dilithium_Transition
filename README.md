# Bitcoin Core with Dilithium Signatures Implementation Notes

**License**: No license specified. All rights reserved for the owner.

## Setup Instructions

To run the program and tests, follow these steps to set up Bitcoin Core with the necessary modifications:

1. **Download Bitcoin Core**:
   - Obtain the Bitcoin Core source code from [GitHub](https://github.com/bitcoin/bitcoin).

2. **Modify Chain Parameters**:
   - Edit the file `./src/kernel/chainparams.cpp`.
   - Change `consensus.nSubsidyHalvingInterval` from `150` to `210000`.

3. **Build Bitcoin Core**:
   - Navigate to the Bitcoin Core folder and execute the following commands:
     ```bash
     rm -rf build
     mkdir build
     cd build
     cmake ..
     cmake --build . -- -j$(sysctl -n hw.ncpu)
     cd build
     ```

4. **Activate Bitcoin Core and Create Wallet**:
   - Run the following commands to start Bitcoin Core in regtest mode and create a wallet:
     ```bash
     bitcoind -regtest -daemon -rpcuser=joshuageorgedai -rpcpassword=333777000 -rpcport=18443
     bitcoin-cli -regtest -rpcuser=joshuageorgedai -rpcpassword=333777000 createwallet myaddress
     ```

5. **Stopping Bitcoin Core**:
   - To stop Bitcoin Core, use:
     ```bash
     bitcoin-cli -regtest -rpcuser=joshuageorgedai -rpcpassword=333777000 stop
     ```
   - To reactivate, repeat the activation commands from step 4.

## Implementation Notes

This implementation is not a complete replication of Bitcoin but serves as a proof-of-concept for integrating Dilithium signatures, as described in the referenced paper. Below are key considerations and trade-offs:

### Limitations Compared to Schnorr Signatures
- **Loss of Signature Aggregation**: Unlike Schnorr signatures, Dilithium signatures do not support signature aggregation for multisignature structures, which may impact efficiency in certain use cases.
- **Larger Signature Size**: Dilithium signatures are significantly larger, requiring larger data structures throughout the system.
- **Layer 2 Compatibility**: The interaction between Dilithium2 encryption and layer 2 solutions (e.g., Lightning Network) requires further research.

## Functional Discrepancies (Phase 1)

The following differences exist between this implementation and standard Bitcoin functionality, with justifications for their acceptability:

- **ScriptPubKey Generation**:
  - **Discrepancy**: The `vout` scriptPubKeys from the Bitcoin chain are not generated using the custom script.
  - **Justification**: An arbitrary scriptPubKey is functionally equivalent to a specific one when implementing the hybrid wallet and `OP_CHECKDILITHIUMSIG`.

- **OP_PUSHDATA2 Opcode**:
  - **Discrepancy**: The `OP_PUSHDATA2` opcode is not explicitly included in the script but is represented when pushing large objects, such as Dilithium2 signatures.
  - **Justification**: This abstraction is sufficient for handling large data pushes in the context of this implementation.

- **Public Key Y-Value Parity**:
  - **Discrepancy**: The `dsa.genkeys()` function does not guarantee an even y-value for the public key.
  - **Justification**: The equations used do not heavily rely on the parity of the y-value of the Schnorr public key, making this acceptable.

- **Script Opcode Decoding**:
  - **Discrepancy**: The program does not read the script in byte format when decoding opcodes.
  - **Justification**: Since the script is already available in opcode format, reading it in bytes is unnecessary for this level of abstraction.

- **Tweaked Public Keys Storage**:
  - **Discrepancy**: Tweaked public keys are not stored on-chain in this implementation.
  - **Justification**: In a production Bitcoin chain, tweaked public keys would be stored on-chain, so this omission is acceptable for demonstration purposes.

## Proposed Changes for Phase 2

To accommodate the increased data requirements of Dilithium signatures, the maximum block weight must be adjusted:

- **Location**: In the Bitcoin source code, the file `consensus/consensus.h` contains the variable `MAX_BLOCK_WEIGHT`, currently set to `4000000`.
- **Proposed Change**: Increase `MAX_BLOCK_WEIGHT` to `68000000` (17 times the original value) to support Phase 2 requirements.
- **Note**: Direct modification of the Bitcoin source code was not performed in this implementation, but the above change would enable the necessary block weight increase.