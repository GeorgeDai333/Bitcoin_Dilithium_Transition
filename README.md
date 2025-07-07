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
- Phase 1: scriptPubKey is not generated with my custom script (should be acceptable because an arbitrary scriptPubKey is no different from a specific one when I am implementing the hybrid wallet and OP_CHECKDILITHIUMSIG)

- Phase 1: The tweaking method needed to remake scriptPubKey from the control block doesn't exactly match Bitcoin's. Also, the information included in the control block doesn't correspond to the information in the official Bitcoin control block. (should be acceptable because the tweak and confirmation method is not a priority for my implementation. The original P2TR method should work well enough.)