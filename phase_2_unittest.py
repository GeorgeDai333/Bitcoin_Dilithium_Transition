import unittest
from phase_2 import *

#In this unittest, we implicitly trust the implementation
#Of Schnorr and Dilithium key generation and verification.
#We also trust that RawProxy and all the functions a proxy can run
#Are properly tested and generate reliable outputs.
class TestPhaseOne(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Runs only once before all tests
        cls.rpc_url = 'http://joshuageorgedai:333777000@127.0.0.1:18443/wallet/myaddress'
        cls.proxy = RawProxy(service_url=cls.rpc_url)
    
    #Test our function that converts x-only pubkeys
    #To Schnorr pubkeys
    def test_x_only_to_schnorr(self):
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()
        x_only = schnorr_to_xonly(schnorr_public_key)
        reverted_x_only = x_only_to_schnorr(x_only)
        #See if the x-values are equal, y-values of dsa.gen_keys() is not guaranteed to be even
        #Unlike the y-values of x_only_to_schnorr(x_only)
        self.assertEqual(schnorr_public_key[0], reverted_x_only[0])

    #Test the pubkey extraction from a tapscript
    def test_pubkey_extraction(self):
        #Simple tapscript and simple extraction test
        tapscript = "20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbad"
        pubkeys_found = extract_schnorr_pubkeys(tapscript)
        expected_simple_output = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
        self.assertEqual(pubkeys_found, expected_simple_output)

        # Example my tapscript
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()
        x_only_pubkey = schnorr_to_xonly(schnorr_public_key)
        #Dilithum keys generated as byte strings
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()
        script = f"OP_IF\n{int.from_bytes(x_only_pubkey, byteorder='little')} OP_CHECKSIG\nOP_ELSE\n{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG\nOP_ENDIF"
        script_formatted = script_byte_format(script).hex()

        #Extract the schnorr pubkey from my script, expected only 1 pubkey outputted
        pubkeys_found_myscript = extract_schnorr_pubkeys(script_formatted)
        expected_my_output = [x_only_pubkey.hex()]
        self.assertEqual(pubkeys_found_myscript, expected_my_output)
    
    #Test if I am getting committed op_returns with proper formatting
    #Also test and see if the commit is not occuring with incorrect format
    def test_op_return_commits(self):
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()

        #Dilithum keys generated as byte strings
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()

        #Generate new taproot address
        address = proxy.getnewaddress("", "bech32m")

        #Fund address 50 bitcoin
        fund(address, 1)

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        #We hard code our scripts used by the hybrid wallet
        #Convert public keys to integers so split() function works properly on the string
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        script_path_schnorr = f"{int.from_bytes(schnorr_to_xonly(schnorr_public_key), byteorder='little')} OP_CHECKSIG"
        script_path_dil = f"{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG"

        scriptPubKey = tweak_pubkey([script_path_schnorr, script_path_dil])

        protocol_ID = b'\x43\x44\x52\x50'
        version = 1
        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest())}"

        witness_opreturn(script_opreturn_hybrid)
        #See if the hashed value is in the list of committed values
        self.assertTrue(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest()[::-1] in committed_opreturns)

        #Test if the wrong protocol ID records as a commit
        wrong_address = proxy.getnewaddress("", "bech32m")
        wrong_unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(wrong_address)['witness_program'])
        wrong_protocol_ID = b'\x43\x44\x52\x51'
        wrong_script_opreturn_hybrid = f"OP_RETURN {wrong_protocol_ID} {version} {int.from_bytes(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest())}"
        witness_opreturn(wrong_script_opreturn_hybrid)
        self.assertFalse(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest()[::-1] in committed_opreturns)

        #Test if the wrong version records as a commit
        wrong_address = proxy.getnewaddress("", "bech32m")
        wrong_unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(wrong_address)['witness_program'])
        protocol_ID = b'\x43\x44\x52\x50'
        wrong_version = 10
        wrong_script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {wrong_version} {int.from_bytes(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest())}"
        witness_opreturn(wrong_script_opreturn_hybrid)
        self.assertFalse(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(scriptPubKey).digest()).digest()[::-1] in committed_opreturns)

    #All of these tests are done with the transaction target
    #Being a hybrid wallet's tweaked public key
    def test_new_op_checksig(self):
        #TRANSACTION WITH NO OP_RETURN TEST
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()

        #Dilithum keys generated as byte strings
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()

        #Generate new taproot address
        address = proxy.getnewaddress("", "bech32m")

        #Fund address 50 bitcoin
        fund(address, 1)

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        #We hard code our scripts used by the hybrid wallet
        #Convert public keys to integers so split() function works properly on the string
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        script_path_schnorr = f"{int.from_bytes(schnorr_to_xonly(schnorr_public_key), byteorder='little')} OP_CHECKSIG"
        script_path_dil = f"{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG"
        
        #Generate scriptPubKey following Bitcoin protocol
        scriptPubKey = tweak_pubkey([script_path_schnorr, script_path_dil])

        #Should send that validation failed (send from our schnorr to unsafe)
        #Because we never made an op_return for our schnorr
        script_path_bool = True
        self.assertFalse(witness_verification(1, unsafe_schnorr_public_key, dil_public_key, scriptPubKey, dil_private_key, script_path_bool, script_path_schnorr, script_path_dil, scriptPubKey))

        #TRANSACTION WITH OP_RETURN BUT NO CONFIRMATION TEST
        protocol_ID = b'\x43\x44\x52\x50'
        version = 1
        #Opreturn example for hybrid script
        script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey([script_path_schnorr, script_path_dil])).digest()).digest())}"
        #Commit unsafe
        witness_opreturn(script_opreturn_hybrid)

        #With this commit, we can send from unsafe to our tweaked pubkey
        #HOWEVER, we have not mined the required amount of blocks to confirm, so this fails
        unsafe_schnorr_public_key = x_only_to_schnorr(unsafe_schnorr_public_key)
        script_path_bool = True
        self.assertFalse(witness_verification(1, unsafe_schnorr_public_key, dil_public_key, scriptPubKey, dil_private_key, script_path_bool, script_path_schnorr, script_path_dil, scriptPubKey))

        #TRANSACTION WITH OP_RETURN AND ALREADY USED PUBKEY TEST
        #Fund address 50 bitcoin
        #This mines 101 blocks, easily enough to confirm the op_return
        fund(address, 1)
        #Trying to do this transaction, even with a confirmed op_return
        #Should fail because unsafe_schnorr_public_key has already been revealed
        unsafe_schnorr_public_key = schnorr_to_xonly(unsafe_schnorr_public_key)
        self.assertTrue(unsafe_schnorr_public_key in revealed_p2tr_pubkeys)
        unsafe_schnorr_public_key = x_only_to_schnorr(unsafe_schnorr_public_key)
        self.assertFalse(witness_verification(1, unsafe_schnorr_public_key, dil_public_key, scriptPubKey, dil_private_key, script_path_bool, script_path_schnorr, script_path_dil, scriptPubKey))

        #TRANSACTION WITH OP_RETURN AND CONFIRMATION TEST
        schnorr_private_key_new, schnorr_public_key_new = dsa.gen_keys()

        #Dilithum keys generated as byte strings
        dil_public_key_new, dil_private_key_new = dilithium.Dilithium2.keygen()

        #Generate new taproot address
        address_new = proxy.getnewaddress("", "bech32m")

        #Fund address 50 bitcoin
        fund(address_new, 1)

        #We hard code our script used by the hybrid wallet
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        #Convert public keys to integers so split() function works properly on the string
        script_path_schnorr_new = f"{int.from_bytes(schnorr_to_xonly(schnorr_public_key_new), byteorder='little')} OP_CHECKSIG"
        script_path_dil_new = f"{int.from_bytes(dil_public_key_new, byteorder='little')} OP_CHECKDILITHIUMSIG"

        scriptPubKey_new = tweak_pubkey([script_path_schnorr_new, script_path_dil_new])

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key_new = bytes.fromhex(proxy.getaddressinfo(address_new)['witness_program'])
        #Opreturn example for hybrid script
        script_opreturn_hybrid_new = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key_new + hashlib.sha256(tweak_pubkey([script_path_schnorr_new, script_path_dil_new])).digest()).digest())}"

        #Commit unsafe public key
        witness_opreturn(script_opreturn_hybrid_new)

        #Fund address 50 bitcoin
        #This mines 101 blocks, easily enough to confirm the op_return
        fund(address, 1)

        #Should succeed because of mined blocks
        unsafe_schnorr_public_key_new = x_only_to_schnorr(unsafe_schnorr_public_key_new)
        script_path_bool_new = True
        self.assertTrue(witness_verification(1, unsafe_schnorr_public_key_new, dil_public_key_new, tweak_pubkey([script_path_schnorr_new, script_path_dil_new]), dil_private_key_new, script_path_bool_new, script_path_schnorr_new, script_path_dil_new, scriptPubKey_new))
        self.assertTrue(schnorr_to_xonly(unsafe_schnorr_public_key_new) in revealed_p2tr_pubkeys)

    #Test the Dilithium path of the script and see if verification is successful
    def test_dilithium_verification(self):
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()

        #Dilithum keys generated as byte strings
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()

        #Generate new taproot address
        address = proxy.getnewaddress("", "bech32m")

        #Fund address 50 bitcoin
        fund(address, 1)

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        #We hard code our scripts used by the hybrid wallet
        #Convert public keys to integers so split() function works properly on the string
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        script_path_schnorr = f"{int.from_bytes(schnorr_to_xonly(schnorr_public_key), byteorder='little')} OP_CHECKSIG"
        script_path_dil = f"{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG"
        
        #Generate scriptPubKey following Bitcoin protocol
        leaf_ver = b'\xc0'
        schnorr_path_bytes = script_byte_format(script_path_schnorr)
        schnorr_path_hash = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(schnorr_path_bytes))+ schnorr_path_bytes).digest()
        dil_path_bytes = script_byte_format(script_path_dil)
        dil_path_hash = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(dil_path_bytes))+ dil_path_bytes).digest()
        hashed_script_list = [schnorr_path_hash, dil_path_hash]
        merkle_branch = (hashlib.sha256("TapBranch".encode()).digest() * 2)
        for branch in sorted(hashed_script_list):
            merkle_branch += branch
        merkle_branch = hashlib.sha256(merkle_branch).digest()
        # Use a NUMS pubkey to force script spending
        NUMS_pubkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        tweak = hashlib.sha256(hashlib.sha256("TapTweak".encode()).digest() + hashlib.sha256("TapTweak".encode()).digest() + NUMS_pubkey + merkle_branch).digest()
        #Generator is the generator we used to get our Schnorr
        #Public key and private key
        internal_pubkey = PublicKey(b'\x02' + NUMS_pubkey, raw=True)
        scriptPubKey = internal_pubkey.tweak_add(tweak).serialize()[1:]

        #Script path boolean to determine which public and private key to use
        #True is Schnorr, False is Dilithium
        script_path_bool = False
        #Using random schnorr public key and target address inputs
        #To show that Dilithium spending is not linked to the Schnorr side
        self.assertTrue(witness_verification(1, schnorr_public_key, dil_public_key, unsafe_schnorr_public_key, dil_private_key, script_path_bool, script_path_schnorr, script_path_dil, scriptPubKey))


if __name__ == '__main__':
    unittest.main()