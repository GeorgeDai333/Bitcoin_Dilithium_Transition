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

        #We hard code our script used by the hybrid wallet
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        #Convert public keys to integers so split() function works properly on the string
        script_hybrid = f"OP_IF\n{int.from_bytes(schnorr_to_xonly(schnorr_public_key), byteorder='little')} OP_CHECKSIG\nOP_ELSE\n{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG\nOP_ENDIF"

        protocol_ID = b'\x43\x44\x52\x50'
        version = 1
        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest())}"

        witness_opreturn(script_opreturn_hybrid)
        #See if the hashed value is in the list of committed values
        self.assertTrue(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest()[::-1] in committed_opreturns)

        #Test if the wrong protocol ID records as a commit
        wrong_address = proxy.getnewaddress("", "bech32m")
        wrong_unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(wrong_address)['witness_program'])
        wrong_protocol_ID = b'\x43\x44\x52\x51'
        wrong_script_opreturn_hybrid = f"OP_RETURN {wrong_protocol_ID} {version} {int.from_bytes(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest())}"
        witness_opreturn(wrong_script_opreturn_hybrid)
        self.assertFalse(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest()[::-1] in committed_opreturns)

        #Test if the wrong version records as a commit
        wrong_address = proxy.getnewaddress("", "bech32m")
        wrong_unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(wrong_address)['witness_program'])
        protocol_ID = b'\x43\x44\x52\x50'
        wrong_version = 10
        wrong_script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {wrong_version} {int.from_bytes(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest())}"
        witness_opreturn(wrong_script_opreturn_hybrid)
        self.assertFalse(hashlib.sha256(wrong_unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest()[::-1] in committed_opreturns)

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

        #We hard code our script used by the hybrid wallet
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        #Convert public keys to integers so split() function works properly on the string
        script_hybrid = f"OP_IF\n{int.from_bytes(schnorr_to_xonly(schnorr_public_key), byteorder='little')} OP_CHECKSIG\nOP_ELSE\n{int.from_bytes(dil_public_key, byteorder='little')} OP_CHECKDILITHIUMSIG\nOP_ENDIF"

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        #Should send that validation failed (send from our schnorr to unsafe)
        #Because we never made an op_return for our schnorr
        script_path_bool = True
        self.assertFalse(witness(1, schnorr_public_key, dil_public_key, unsafe_schnorr_public_key, dil_private_key, script_path_bool, script_hybrid))

        #TRANSACTION WITH OP_RETURN BUT NO CONFIRMATION TEST
        protocol_ID = b'\x43\x44\x52\x50'
        version = 1
        #Opreturn example for hybrid script
        script_opreturn_hybrid = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key + hashlib.sha256(tweak_pubkey(schnorr_public_key, script_hybrid)).digest()).digest())}"
        #Commit unsafe
        witness_opreturn(script_opreturn_hybrid)

        #With this commit, we can send from unsafe to our tweaked pubkey
        #HOWEVER, we have not mined the required amount of blocks to confirm, so this fails
        unsafe_schnorr_public_key = x_only_to_schnorr(unsafe_schnorr_public_key)
        script_path_bool = True
        self.assertFalse(witness(1, unsafe_schnorr_public_key, dil_public_key, tweak_pubkey(schnorr_public_key, script_hybrid), dil_private_key, script_path_bool, script_hybrid))

        #TRANSACTION WITH OP_RETURN AND ALREADY USED PUBKEY TEST
        #Fund address 50 bitcoin
        #This mines 101 blocks, easily enough to confirm the op_return
        fund(address, 1)
        #Trying to do this transaction, even with a confirmed op_return
        #Should fail because unsafe_schnorr_public_key has already been revealed
        unsafe_schnorr_public_key = schnorr_to_xonly(unsafe_schnorr_public_key)
        self.assertTrue(unsafe_schnorr_public_key in revealed_p2tr_pubkeys)
        unsafe_schnorr_public_key = x_only_to_schnorr(unsafe_schnorr_public_key)
        self.assertFalse(witness(1, unsafe_schnorr_public_key, dil_public_key, tweak_pubkey(schnorr_public_key, script_hybrid), dil_private_key, script_path_bool, script_hybrid))

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
        script_hybrid_new = f"OP_IF\n{int.from_bytes(schnorr_to_xonly(schnorr_public_key_new), byteorder='little')} OP_CHECKSIG\nOP_ELSE\n{int.from_bytes(dil_public_key_new, byteorder='little')} OP_CHECKDILITHIUMSIG\nOP_ENDIF"

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key_new = bytes.fromhex(proxy.getaddressinfo(address_new)['witness_program'])
        #Opreturn example for hybrid script
        script_opreturn_hybrid_new = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key_new + hashlib.sha256(tweak_pubkey(schnorr_public_key_new, script_hybrid_new)).digest()).digest())}"

        #Commit unsafe public key
        witness_opreturn(script_opreturn_hybrid_new)

        #Fund address 50 bitcoin
        #This mines 101 blocks, easily enough to confirm the op_return
        fund(address, 1)

        #Should succeed because of mined blocks
        unsafe_schnorr_public_key_new = x_only_to_schnorr(unsafe_schnorr_public_key_new)
        script_path_bool_new = True
        self.assertTrue(witness(1, unsafe_schnorr_public_key_new, dil_public_key_new, tweak_pubkey(schnorr_public_key_new, script_hybrid_new), dil_private_key_new, script_path_bool_new, script_hybrid_new))

    #Test the Dilithium path of the script and see if verification is successful
    def test_dilithium_verification(self):
        schnorr_private_key, schnorr_public_key = dsa.gen_keys()

        #Dilithum keys generated as byte strings
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()

        #Generate new taproot address
        address = self.proxy.getnewaddress("", "bech32m")

        #Fund address 50 bitcoin
        fund(address, 1)

        #We hard code our script used by the hybrid wallet
        #Hypothetical opcode byte for OP_CHECKDILITHIUMSIG is b'\xc0', which is one of the unassigned opcode bytes
        script = f"OP_IF\n{schnorr_public_key} OP_CHECKSIG\nOP_ELSE\n{dil_public_key} OP_CHECKDILITHIUMSIG\nOP_ENDIF"

        # Make the generated address the unsafe address we transfer coins away from
        unsafe_schnorr_public_key = bytes.fromhex(proxy.getaddressinfo(address)['witness_program'])

        #Script path boolean to determine which public and private key to use
        #True is Schnorr, False is Dilithium
        script_path_bool = False
        self.assertTrue(witness(1, schnorr_public_key, dil_public_key, unsafe_schnorr_public_key, dil_private_key, script_path_bool, script))


if __name__ == '__main__':
    unittest.main()