License: No License as of now. Thus, all rights as reserved for the owner.

NOTE: To run the program and tests, the user needs to download Bitcoin Core from GitHub at https://github.com/bitcoin/bitcoin.

After the download, edit the ./src/kernel/chainparams.cpp file, changing consensus.nSubsidyHalvingInterval to 210000 from 150.

Then, run the following commands in the Bitcoin folder to build Bitcoin Core
rm -rf build
mkdir build
cd build
cmake ..
cmake --build . -- -j$(sysctl -n hw.ncpu)
cd build

Finally, run these commands to activate Bitcoin Core and create the wallet
bitcoind -regtest -daemon -rpcuser=joshuageorgedai -rpcpassword=333777000 -rpcport=18443
bitcoin-cli -regtest -rpcuser=joshuageorgedai -rpcpassword=333777000 createwallet myaddress

If the user wants to stop Bitcoin Core, run
bitcoin-cli -regtest -rpcuser=joshuageorgedai -rpcpassword=333777000 stop
reactivate using the commands in the previous paragraph

This is not a perfect implementation of Bitcoin, but it serves as an illustration for the ideas the implementation of Dilithium signatures mentioned in my paper.
[everything else negative here]

For example, some advantages provided by Schnorr signatures would be lost, such as signature aggregation for multisignature structures. Needless to say, the signatures for Dilithium are much larger, meaning almost everything needs to be larger. Also, the interaction between Dilithium2 encryption and layer 2 solutions (such as the lightning network) still needs to be studied.

Below, I list the discrepencies of my code's functionalities to real Bitcoin code, as well as why these functional differences are acceptable:
- Phase 1: The vout scriptPubKeys from the bitcoin chain are not generated with my custom script (should be acceptable because an arbitrary scriptPubKey is no different from a specific one when I am implementing the hybrid wallet and OP_CHECKDILITHIUMSIG)

- Phase 1: I don't have the OP_PUSHDATA2 opcode in my script. However, I do represent that opcode whenever I need to push a very large object (such as the Dilithium2 signature).

- Phase 1: dsa.genkeys() is not guaranteed to have an even y-value for the public key. (This is acceptable because my equations don't excessively depend on the parity of the y-value of the Schnorr public key)

- Phase 1: My program is not reading my byte script when decoding the script's opcodes. (This level of abstraction is acceptable, as it is unnecessary to read the script in bytes when I already have the script in opcode format)

- Phase 1: My tweaked public keys are not stored on-chain. (Acceptable because, in a real Bitcoin chain, the tweaked public keys would be stored on-chain)

EXTERNAL CHANGES FOR PHASE 2:

While I couldn't directly edit Bitcoin source code with my python code, I have located the line of code that dictates maximum block weight. In Bitcoin source code's consensus/consensus.h file, there is a variable called MAX_BLOCK_WEIGHT, which is set to 4000000. To implement my phase 2's change of increasing block weight by 17 times, I would simply set that variable to 68000000.