# !/usr/bin/env python3
# !pip install ecdsa
# !pip install btclib
# !pip install python-bitcoinlib
# !pip install bitcoinlib
# !brew install pkg-config
# !brew install secp256k1
# !pip install secp256k1
# !pip install coincurve
# !pip install bech32

from multiprocessing import Value
from bitcoin.core import ValidationError
from bitcoin.rpc import RawProxy
from btclib.ecc.ssa import sign, verify
from btclib.ecc import dsa
from ecdsa import SECP256k1
from ecdsa.ecdsa import generator_256
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.ellipticcurve import Point
import hashlib
import struct
import binascii
from dilithium_py import dilithium
from secp256k1 import PublicKey
from bech32 import bech32_encode, convertbits, bech32_decode

#global proxy
rpc_url = 'http://joshuageorgedai:333777000@127.0.0.1:18443/wallet/myaddress'
proxy = RawProxy(service_url=rpc_url)

#global witness stack
witness_stack = []

#global execution stack
exec_stack = []

#global confirmation stack
confirmation_stack = []

#global list of previously revealed public keys
revealed_p2tr_pubkeys = set()

#global list of opreturns with specific protocol ID and version
committed_opreturns = {}

def fund(address, amount: int):
    """ Generates "amount" * 50 bitcoins to given address, might be halved if over 210000 blocks"""
    global proxy
    proxy.generatetoaddress(amount, address)
    proxy.generatetoaddress(101, proxy.getnewaddress())  # confirm transaction

def double_sha256(data) -> bytes:
    if isinstance(data, str):
        data = data.encode()  # Convert string to bytes (UTF-8)
    elif isinstance(data, bytearray):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError("Input must be bytes, bytearray, or str")
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

#little-endian encoding of script length
def compact_size(length):
    if length < 0xfd:
        return struct.pack('B', length)  # 1 byte
    elif length <= 0xffff:
        return b'\xfd' + struct.pack('<H', length)  # 0xfd + 2 bytes
    elif length <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', length)  # 0xfe + 4 bytes
    else:
        return b'\xff' + struct.pack('<Q', length)  # 0xff + 8 bytes

def schnorr_to_xonly(schnorr_public_key):
    x = schnorr_public_key[0]
    x_bytes = x.to_bytes(32, byteorder='big')
    return x_bytes

def x_only_to_schnorr(x_only_public_key: bytes):
    """
    Transforms an x-only public key to an x and y coordinate
    using the standard of even y-coordinates
    """
    pubkey_even = PublicKey(b'\x02' + x_only_public_key, raw=True)
    uncompressed_pubkey_even = pubkey_even.serialize(compressed=False)
    # Extract coordinates explicitly
    x_coord = uncompressed_pubkey_even[1:33]   # bytes 1-32
    y_coord = uncompressed_pubkey_even[33:] 
    # Convert bytes to integers
    x_int = int.from_bytes(x_coord, 'big')
    y_int = int.from_bytes(y_coord, 'big')
    return (x_int, y_int)

#Format script with only bytes. Specially coded for the script suggested in my paper.
#All opcode bytes checked against bytes provided by Bitcoin source code
def script_byte_format(script: str):
    script_preprocessed_list = script.split()
    #Everything in the list is a string
    #Check for anything that can turn into an integer
    #If it can, convert it back into a byte string
    script_list = []
    for item in script_preprocessed_list:
        try:
            is_pubkey = int(item)
            length = (is_pubkey.bit_length() + 7) // 8
            item = is_pubkey.to_bytes(length, 'little')
            script_list.append(item)
        except ValueError:
            script_list.append(item)
    script_byte_list = []
    #All items' byte form follows Bitcoin protocol
    for item in script_list:
        #Check for opcode first
        if item == "OP_RETURN":
            script_list.remove("OP_RETURN")
            script_byte_list = script_list
            script_byte_list.insert(0, b'\x6a')
            script_list = []
            for subitem in script_byte_list:
                if not isinstance(subitem, bytes) and isinstance(subitem, str):
                    script_list.append(subitem[2:-1].encode())
                elif isinstance(subitem, bytes):
                    script_list.append(subitem)
            script_byte_list = script_list
            break
        elif item == "OP_IF":
            script_byte_list.append(b'\x63')
        elif item == "OP_CHECKSIG":
            script_byte_list.append(b'\xac')
        elif item == "OP_ELSE":
            script_byte_list.append(b'\x67')
        elif item == "OP_CHECKDILITHIUMSIG":
            script_byte_list.append(b'\xc0')
        elif item == "OP_ENDIF":
            script_byte_list.append(b'\x68')
        elif item == "OP_DUP":
            script_byte_list.append(b'\x76')
        elif item == "OP_EQUALVERIFY":
            script_byte_list.append(b'\x88')
        elif item == "OP_HASH256":
            script_byte_list.append(b'\xaa')
        #If byte count is less than 75, we use no OP_PUSHDATA
        #After checking if it is an opcode, we are certain the item is a public key
        elif len(item) < 75 and isinstance(item, bytes):
            script_byte_list.append(struct.pack('B', len(item)))
            script_byte_list.append(item)
        #If byte count is less than 65535 but greater than 255, 
        #We can fit in 2 hexedecimals, which we will signal with b'\x4d
        #(OP_PUSHDATA2) As per Bitcoin protocol
        elif len(item) < 65535 and len(item) > 255 and isinstance(item, bytes):
            script_byte_list.append(b'\x4d')
            temp_byte_len = struct.pack('>H', len(item))
            #Flip for little-endian value
            temp_byte_len = temp_byte_len[::-1]
            script_byte_list.append(temp_byte_len)
            script_byte_list.append(item)
    return b''.join(script_byte_list)

def tweak_pubkey(script_list:list) -> bytes:
    """
    Takes in a Schnorr public key (coordinate form) and a list of scripts (string form)
    Returns a tweaked public key (Based on NUMS Pubkey)
    """
    leaf_ver = b'\xc0'
    hashed_script_list = []
    for script in script_list:
        path_bytes = script_byte_format(script)
        path_hash = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(path_bytes))+ path_bytes).digest()
        hashed_script_list.append(path_hash)
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
    tweakedPubKey = internal_pubkey.tweak_add(tweak).serialize()[1:]
    return tweakedPubKey

def msg_hash(amount_spent: float, script:str):
    """
    Creates a message hash for our transaction using information from fabricated transactions
    amount_spent: the amount we are spending in BTC
    schnorr_public_key: we only need the x coordinate of our schnorr public key, which we isolate later
    """
    global proxy

    #Epoch is 0x00 for Taproot
    epoch = 0x00
    #Hash type is 0x00 for SIGHASH_ALL
    hash_type = 0x00
    #Spend type is 0x02 for script-path spending
    spend_type = 0x02
    #Leaf version is 0xc0 (BIP 341)
    leaf_version = 0xc0
    #Script code is the script we are spending from
    
    #Generate a fake transaction to use for our txid info
    #We can do this without loss of generality because we assume that
    #Our transaction data and previous transaction data would be random in a real Bitcoin chain
    receiver_address = proxy.getnewaddress("", "bech32m")
    amount_to_send = amount_spent
    txid = proxy.sendtoaddress(receiver_address, amount_to_send)
    # Mine a block to confirm transaction (only necessary for regtest)
    proxy.generatetoaddress(1, proxy.getnewaddress())
    # Get transaction info
    transaction_info = proxy.gettransaction(txid)
    # Get the raw hex
    raw_hex = transaction_info['hex']
    # Decode the raw transaction
    transaction_decoded = proxy.decoderawtransaction(raw_hex)
    # print(f"Fake transaction: {transaction_decoded}")

    #Serialize as 32-bit little-endian integers
    nVersion_32bit = struct.pack('<I', transaction_decoded['version'])
    nLocktime_32bit = struct.pack('<I', transaction_decoded['locktime'])
    #previous outputs (vin section), which will be hashed
    #format is txid (32 bytes, little-endian) + vout (32-bit, little-endian)
    prev_outputs_list = []
    #sequences (vin section), which will be hashed
    #sequences should be a 32-bit little-endian
    sequences_list = []
    for trans in transaction_decoded['vin']:
        #previous outputs handling, convert all to little-endian
        temp_txid = binascii.unhexlify(trans['txid'])
        temp_txid = temp_txid[::-1]
        temp_vout = struct.pack('<I', trans['vout'])
        prev_outputs_list.append(temp_txid+temp_vout)
        #sequence handling, convert all to little-endian
        sequences_list.append(struct.pack('<I', trans['sequence']))
    
    #spent amounts (vout section), which will be hashed
    #format is 64-bit little endian (<Q instead of <I)
    spent_amounts_list = []
    #scriptpubkeys (vout section), which will be hashed
    #Although our script would undoubtedly generate a different scriptPubKey, we can use the random transaction's scriptPubKey
    #Without loss of generality because the scriptPubKey should be pseudo-random
    scriptpubkeys_list = []
    #output (vout section), which will be hashed
    #format is value (8 bytes, little-endian) + scriptPubKey (compact size length + script bytes)
    outputs_list = []
    for transout in transaction_decoded['vout']:
        #Handle spent amounts, converted into satoshis
        temp_val = struct.pack('<Q', int(transout['value'] * 100000000))
        spent_amounts_list.append(temp_val)
        #Handle scriptpubkey list
        temp_scriptpubkey = binascii.unhexlify(transout['scriptPubKey']['hex'])
        temp_scriptpubkey = temp_scriptpubkey[::-1]
        scriptpubkeys_list.append(temp_scriptpubkey)
        #Handle outputs list
        outputs_list.append(temp_val + temp_scriptpubkey)

    #We hard code the script to match Bitcoin Opcode protocol
    #And to match the hybrid script we wish to create
    script = script_byte_format(script)
    tapleaf_hash = hashlib.sha256(bytes([leaf_version]) + compact_size(len(script)) +script).digest()
    
    #Combine previous outputs and double hash
    prev_outputs_hash = double_sha256(b''.join(prev_outputs_list))

    #Combine sequences list and double hash
    sequences_hash = double_sha256(b''.join(sequences_list))

    #Combine spent amounts and double hash
    spent_amounts_hash = double_sha256(b''.join(spent_amounts_list))

    #Combine script pubkeys and double hash
    script_pubkeys_hash = double_sha256(b''.join(scriptpubkeys_list))

    #Combine outputs and double hash
    outputs_hash = double_sha256(b''.join(outputs_list))

    #Find number of inputs in bytes
    input_num_in_bytes = struct.pack('B',len(transaction_decoded['vin']))

    #Order of sigmsg taken from Bitcoin
    #Though it should be noted order can be scrambled without loss of generality
    sigmsg = (
        bytes([epoch]) + 
        bytes([hash_type]) + 
        nVersion_32bit +
        nLocktime_32bit + 
        prev_outputs_hash +
        spent_amounts_hash +
        script_pubkeys_hash +
        sequences_hash +
        outputs_hash +
        bytes([spend_type]) +
        input_num_in_bytes +
        tapleaf_hash
    )

    message_hash = double_sha256(sigmsg)
    return message_hash

def confirm_tweak(script, scriptPubKey):
    global witness_stack
    control_block = witness_stack.pop()
    temp_script_bytes = script_byte_format(script)
    leaf_ver = bytes([control_block[0]])
    this_script_hashed = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(temp_script_bytes))+ temp_script_bytes).digest()
    other_scripts_hashed = control_block[33:]
    merkle_branch = (hashlib.sha256("TapBranch".encode()).digest() * 2)
    script_list = [this_script_hashed, other_scripts_hashed]
    for branch in sorted(script_list):
        merkle_branch += branch
    merkle_branch = hashlib.sha256(merkle_branch).digest()
    tweak = hashlib.sha256(hashlib.sha256("TapTweak".encode()).digest() + hashlib.sha256("TapTweak".encode()).digest() + control_block[1:33] + merkle_branch).digest()
    #Generator is the generator we used to get our Schnorr
    #Public key and private key
    internal_pubkey = PublicKey(b'\x02' + control_block[1:33], raw=True)
    calcedScriptPubKey = internal_pubkey.tweak_add(tweak).serialize()[1:]
    if(calcedScriptPubKey != scriptPubKey):
        raise ValidationError("Script Public Key doesn't match spending scripts")

def op_if():
    global witness_stack
    global exec_stack
    #Raise error if stack is empty
    if(not witness_stack):
        raise ValueError("Witness stack is empty (OP_IF)")


    #Boolean should be on top of the witness stack
    if_bool = witness_stack.pop()
    #We add given boolean to the execution stack
    exec_stack.append(if_bool)

def op_checksig() -> bool:
    global witness_stack
    global exec_stack
    global proxy
    
    #Target address popped first, public key next
    #Handle cases where execution stack is empty or has true on top
    if(not exec_stack):
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKSIG)")
        target_address = witness_stack.pop()
        x_only_pubkey = witness_stack.pop()
        op_return_hash = hashlib.sha256(x_only_pubkey + hashlib.sha256(target_address).digest()).digest()[::-1]
        #Check if public key is unrevealed and committed
        if x_only_pubkey in revealed_p2tr_pubkeys:
            return False
        # Need to reverse the hash because of endian disparity
        elif op_return_hash not in committed_opreturns or proxy.getblockchaininfo()['blocks'] - committed_opreturns[op_return_hash] < 10:
            revealed_p2tr_pubkeys.add(x_only_pubkey)
            return False
        revealed_p2tr_pubkeys.add(x_only_pubkey)
        return True
        
    elif exec_stack[-1]:
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKSIG)")
        target_address = witness_stack.pop()
        x_only_pubkey = witness_stack.pop()
        op_return_hash = hashlib.sha256(x_only_pubkey + hashlib.sha256(target_address).digest()).digest()[::-1]
        #Check if public key is unrevealed and committed
        if x_only_pubkey in revealed_p2tr_pubkeys:
            return False
        # Need to reverse the hash because of endian disparity
        elif op_return_hash not in committed_opreturns or proxy.getblockchaininfo()['blocks'] - committed_opreturns[op_return_hash] < 10:
            revealed_p2tr_pubkeys.add(x_only_pubkey)
            return False
        revealed_p2tr_pubkeys.add(x_only_pubkey)
        return True
        

def op_else():
    global exec_stack
    #If execution stack is empty
    if(not exec_stack):
        raise ValueError("Execution stack is empty (OP_ELSE)")
    #Flip the boolean in execution stack
    exec_stack[-1] = not exec_stack[-1]

def op_checkdilithiumsig(msg):
    global witness_stack
    global exec_stack
    
    #Signature popped first, public key next
    #Handle cases where execution stack is empty or has true on top
    if(not exec_stack):
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKDILITHIUMSIG)")
        signature = witness_stack.pop()
        dil_public_key = witness_stack.pop()
        return dilithium.Dilithium2.verify(dil_public_key, msg, signature)
    elif exec_stack[-1]:
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKDILITHIUMSIG)")
        signature = witness_stack.pop()
        dil_public_key = witness_stack.pop()
        return dilithium.Dilithium2.verify(dil_public_key, msg, signature)

def op_endif():
    global exec_stack
    #If execution stack is empty
    if(not exec_stack):
        raise ValueError("Execution stack is empty (OP_ENDIF)")
    #Remove the last value in execution stack
    exec_stack.pop()

def process_script(msg, scriptPubKey):
    """
    Message is necessary input, as Bitcoin generates it from transaction data
    Since we generated the message from transaction data in the msg_hash function
    We will forgo the generation here
    """
    global confirmation_stack
    global witness_stack

    script = witness_stack.pop()
    script_list = script.split()
    #Run through all the opcodes
    for item in script_list:
        #Check for opcode first
        if item == "OP_IF":
            op_if()
        elif item == "OP_CHECKSIG":
            confirmation_stack.append(op_checksig())
        elif item == "OP_ELSE":
            op_else()
        elif item == "OP_CHECKDILITHIUMSIG":
            confirmation_stack.append(op_checkdilithiumsig(msg))
        elif item == "OP_ENDIF":
            op_endif()
        elif item == "OP_RETURN":
            confirmation_stack.append(op_return(script_list))
    
    #Clear confirmation stack of all None return values
    confirmation_stack = [item for item in confirmation_stack if item is not None]
    #If there is no confirmation, raise an error
    if(not confirmation_stack):
        raise ValueError("No validation script ran")
    #Confirm tweak confirms that our scriptPubKey matches our inputs
    confirm_tweak(script, scriptPubKey)
    return confirmation_stack.pop()

def op_return(script_list):
    """
    Don't forget, everything in script list is a string
    """
    global witness_stack
    global committed_opreturns
    global proxy

    if (not witness_stack):
        raise ValueError("Witness stack is empty (process_opreturn_script)")

    #Define acceptable conditions and add to committed list
    accepted_versions = ["1"]
    designated_protocol_ID = b'\x43\x44\x52\x50'
    if (script_list[0] == "OP_RETURN"):
        if len(script_list) == 4 and (script_list[1] == f"{designated_protocol_ID}" and script_list[2] in accepted_versions):
            committed_opreturns[int(script_list[3]).to_bytes(32, 'little')] = proxy.getblockchaininfo()['blocks']
    else:
        raise ValueError("Not an OP_RETURN (process_opreturn_script)")
    #Clear witness stack as OP_RETURN should leave nothing on the stack except the control block
    witness_stack[1:] = []
    return True

def witness_verification(amount, schnorr_public_key, dil_public_key, target_address, dil_private_key, script_path_bool: bool, script_path_schnorr: str, script_path_dil: str, scriptPubKey):
    """
    Instead of Schnorr private key, we need the target address
    """
    global witness_stack
    global proxy
    #Follow Bitcoin's protocol for hashing leaf scripts
    #Leaf version is 0xc0 as per BIP 341
    leaf_ver = b'\xc0'
    if script_path_bool == True:
        revealed_script = script_path_schnorr
        script_bytes = script_byte_format(script_path_dil)
        tapleaf_hashed_script = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(script_bytes))+ script_bytes).digest()
    else:
        revealed_script = script_path_dil
        script_bytes = script_byte_format(script_path_schnorr)
        tapleaf_hashed_script = hashlib.sha256((hashlib.sha256("TapLeaf".encode()).digest() * 2) +leaf_ver+compact_size(len(script_bytes))+ script_bytes).digest()
    #Knowing our hashed script, we can recompute our tweaked pubkey
    #Following Bitcoin protocol, we append the control block to the bottom of the stack
    #Our script uses a NUMS public key to force script path spending
    nums_pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000001"

    # Convert hex to bytes
    nums_pubkey_bytes = bytes.fromhex(nums_pubkey_hex)
    control_block = leaf_ver + nums_pubkey_bytes + tapleaf_hashed_script
    witness_stack.append(control_block)
    #Generate the message and signatures
    #msg generated uing only the revealed script
    msg = msg_hash(amount, revealed_script)
    dil_sig = dilithium.Dilithium2.sign(dil_private_key, msg)
    #Witness stack executes on a LIFO basis, so the script goes in last and public key and 
    #signature goes in first
    if script_path_bool == True:
        witness_stack.append(schnorr_to_xonly(schnorr_public_key))
        witness_stack.append(target_address)
    else:
        witness_stack.append(dil_public_key)
        witness_stack.append(dil_sig)
    #After, we append the script
    witness_stack.append(revealed_script)
    #NOW, we execute everything on the witness stack in order
    #Process script processes all the opcodes in the script
    #In the process script function, we also confirm the tweak
    #Process script processes all the opcodes in the script
    validation = process_script(msg, scriptPubKey)
    return validation

def extract_schnorr_pubkeys(tapscript_hex) -> list:
    pubkeys = []
    script_bytes = bytes.fromhex(tapscript_hex)
    i = 0

    while i < len(script_bytes) - 33:  # at least 33 bytes remain
        opcode = script_bytes[i]

        #Check for 0x4d (PUSH [next 2 bytes] BYTES)
        if opcode == 0x4d:
            #Find the next 2 bytes
            next_two_opcode = script_bytes[i+1:i+3]
            #Skip through that many indexes
            skip_index = int.from_bytes(next_two_opcode, 'little')
            i += skip_index + 2
            continue
        # Check for 0x20 (PUSH 32 bytes)
        if opcode == 0x20:
            # Extract next 32 bytes as potential pubkey
            potential_pubkey = script_bytes[i+1:i+33]

            # Next byte after potential_pubkey
            next_opcode = script_bytes[i+33]

            # Check if next opcode is OP_CHECKSIG (0xac) or OP_CHECKSIGVERIFY (0xad)
            if next_opcode in (0xac, 0xad):
                pubkey_hex = potential_pubkey.hex()
                pubkeys.append(pubkey_hex)

                # Move pointer past this sequence
                i += 33
                continue  # restart loop

        i += 1  # increment pointer by 1 if no match

    return pubkeys

def get_previous_pubkeys():
    """
    Gathers all revealed Schnorr public keys from input scripts
    """
    global revealed_p2tr_pubkeys
    global proxy

    block_height = proxy.getblockcount()
    for height in range(block_height + 1):
        block_hash = proxy.getblockhash(height)
        block = proxy.getblock(block_hash, 2)  # verbosity=2 for full details
        
        #Find all previously revealed Schnorr public keys (in hex)
        for tx in block["tx"]:
            for vin in tx["vin"]:
                temp_pubkey_list = []
                #Skip the coinbase input in the genesis block
                if 'coinbase' in vin:
                    continue
                input_list = vin["txinwitness"]
                
                #Check if it is a P2TR key spend path
                if len(input_list) == 1:
                    revealed_p2tr_pubkeys.add(input_list[0])
                #Check SegWit case (no script)
                elif len(input_list) == 2:
                    #Second value is the Schnorr public key
                    revealed_p2tr_pubkeys.add(input_list[1])
                elif len(input_list) > 2:
                    #2nd to last item is always the script, as the last item is always the control block
                    script = input_list[-2]
                    temp_pubkey_list = extract_schnorr_pubkeys(script)
                
                for pubkey in temp_pubkey_list:
                    revealed_p2tr_pubkeys.add(pubkey)

def p2dil_transaction_info_format(amount_to_send:float, decoded):
    dil_msg_list = []
    for vin in decoded['vin']:
        dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()
        #Copied scriptcode's structure from P2WPKH
        p2dil_scriptcode = f"OP_DUP OP_HASH256 {int.from_bytes(double_sha256(dil_public_key), byteorder='little')} OP_EQUALVERIFY OP_CHECKDILITHIUMSIG"
        #Cut the amount into smaller bits to simulate multiple UTXOs
        amount = round(amount_to_send/len(vin), 7)
        dil_msg = msg_hash(amount, p2dil_scriptcode)
        dil_sig = dilithium.Dilithium2.sign(dil_private_key, dil_msg)

        #Add items into txinwitness, converted to hex
        #In Bitcoin protocol, earlier items are on top of the stack
        add_list = [dil_sig.hex(), dil_public_key.hex()]
        vin['txinwitness'] = add_list
        dil_msg_list.append(dil_msg)
    
    dil_vout_list = []
    for vout in decoded['vout']:
        reciever_dil_public_key, reciever_dil_private_key = dilithium.Dilithium2.keygen()
        hashed_dil_pubkey = double_sha256(reciever_dil_public_key)
        hrp = "bc"
        # Change witness verion to v2 for our P2DIL address type
        # Differentiating it from Taproot (v1) and SegWit (v0)
        # Header should be 'bc1z', as this is version 2
        witness_version = 2
        witness_program = hashed_dil_pubkey

        # Convert witness program bytes from 8-bit to 5-bit groups
        data = [witness_version] + convertbits(witness_program, 8, 5)
        address = bech32_encode(hrp, data)


        new_scriptPubKey_section = {'hex' : hashed_dil_pubkey.hex(), 'address':address, 'type':'witness_v1_dilithium'}
        vout['scriptPubKey'] = new_scriptPubKey_section
        dil_vout_list.append(new_scriptPubKey_section)
    
    return decoded, dil_msg_list, dil_vout_list

def main():
    number = 10
    revealed_pubkey_checklist = []
    for i in range(number):
        receiver_address = proxy.getnewaddress("", "bech32m")
        amount_to_send = 1
        txid = proxy.sendtoaddress(receiver_address, amount_to_send)
        # Mine a block to confirm transaction (only necessary for regtest)
        proxy.generatetoaddress(1, proxy.getnewaddress())
        # Get transaction info
        transaction_info = proxy.gettransaction(txid)
        # Get the raw hex
        raw_hex = transaction_info['hex']
        # Decode the raw transaction
        transaction_decoded = proxy.decoderawtransaction(raw_hex)
        # Add the first generated vin to the checklist
        revealed_pubkey_checklist.append(transaction_decoded['vin'][0]['txinwitness'][0])

    get_previous_pubkeys()

    for pubkey in revealed_pubkey_checklist:
        print(pubkey in revealed_p2tr_pubkeys)
    

    #TODO: Phase 2 would need a new way of calculating scriptPubKey or just not at all,
    # as we can't just tweak the public key anymore bcs Dilithium2 pub keys are too long

    #TODO: Need to make an entire P2DIL with a semi-custom JSON output



if __name__ == "__main__":
    main()