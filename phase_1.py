# !/usr/bin/env python3
# !pip install ecdsa
# !pip install btclib
# !pip install python-bitcoinlib
# !pip install bitcoinlib
# !brew install pkg-config
# !brew install secp256k1
# !pip install secp256k1

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
#global witness stack
witness_stack = []

#global execution stack
exec_stack = []

#global confirmation stack
confirmation_stack = []

def fund(proxy, address, amount: int):
    """ Generates "amount" * 50 bitcoins to given address, might be halved if over 210000 blocks"""
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
        if item == "OP_IF":
            script_byte_list.append(b'\x63')
        elif item == "OP_CHECKSIG":
            script_byte_list.append(b'\xac')
        elif item == "OP_ELSE":
            script_byte_list.append(b'\x67')
        elif item == "OP_CHECKDILITHIUMSIG":
            script_byte_list.append(b'\xc0')
        elif item == "OP_ENDIF":
            script_byte_list.append(b'\x68')
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


def msg_hash(proxy, amount_spent: float, schnorr_public_key, dil_public_key, script):
    """
    Creates a message hash for our transaction using information from fabricated transactions
    amount_spent: the amount we are spending in BTC
    schnorr_public_key: we only need the x coordinate of our schnorr public key, which we isolate later
    """
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
    receiver_address = proxy.getnewaddress()
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
    x_only_pubkey = schnorr_to_xonly(schnorr_public_key)
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

def tweak_pubkey(internal_schnorr_pubkey, script:str) -> bytes:
    """
    Takes in a Schnorr public key (coordinate form) and a script (string form)
    Returns a tweaked public key 
    """
    temp_script_byte = script_byte_format(script)
    x_only_pubkey = schnorr_to_xonly(internal_schnorr_pubkey)
    leaf_version = 0xc0
    leaf_hash = hashlib.sha256(bytes([leaf_version])+compact_size(len(temp_script_byte))+temp_script_byte).digest()
    tweak = hashlib.sha256((hashlib.sha256("TapTweak".encode()).digest()*2) + x_only_pubkey + leaf_hash).digest()
    internal_pubkey = PublicKey(b'\x02' + x_only_pubkey, raw=True)
    tweakedPubKey = internal_pubkey.tweak_add(tweak).serialize()[1:]
    return tweakedPubKey

def msg_hash(proxy, amount_spent: float, schnorr_public_key, dil_public_key, script):
    """
    Creates a message hash for our transaction using information from fabricated transactions
    amount_spent: the amount we are spending in BTC
    schnorr_public_key: we only need the x coordinate of our schnorr public key, which we isolate later
    """
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
    receiver_address = proxy.getnewaddress()
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
    x_only_pubkey = schnorr_to_xonly(schnorr_public_key)
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

def op_checksig(msg):
    global witness_stack
    global exec_stack
    
    #Signature popped first, public key next
    #Handle cases where execution stack is empty or has true on top
    if(not exec_stack):
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKSIG)")
        signature = witness_stack.pop()
        x_only_pubkey = witness_stack.pop()
        return verify(msg, x_only_pubkey, signature)
    elif exec_stack[-1]:
        if(len(witness_stack) < 2):
            raise ValueError("Witness stack is empty (OP_CHECKSIG)")
        signature = witness_stack.pop()
        x_only_pubkey = witness_stack.pop()
        return verify(msg, x_only_pubkey, signature)

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
            confirmation_stack.append(op_checksig(msg))
        elif item == "OP_ELSE":
            op_else()
        elif item == "OP_CHECKDILITHIUMSIG":
            confirmation_stack.append(op_checkdilithiumsig(msg))
        elif item == "OP_ENDIF":
            op_endif()
    
    #Clear confirmation stack of all None return values
    confirmation_stack = [item for item in confirmation_stack if item is not None]
    #If there is no confirmation, raise an error
    if(not confirmation_stack):
        raise ValueError("No validation script ran")
    #Confirm tweak confirms that our scriptPubKey matches our inputs
    confirm_tweak(script, scriptPubKey)
    return confirmation_stack.pop()

def witness_verification(proxy, amount, schnorr_public_key, dil_public_key, schnorr_private_key, dil_private_key, script_path_bool: bool, script_path_schnorr: str, script_path_dil: str, scriptPubKey):
    global witness_stack
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
    msg = msg_hash(proxy, amount, schnorr_public_key, dil_public_key, revealed_script)
    schnorr_sig = sign(msg, schnorr_private_key)
    dil_sig = dilithium.Dilithium2.sign(dil_private_key, msg)
    #Witness stack executes on a LIFO basis, so the script goes in last and public key and 
    #signature goes in first
    if script_path_bool == True:
        witness_stack.append(schnorr_to_xonly(schnorr_public_key))
        witness_stack.append(schnorr_sig)
    else:
        witness_stack.append(dil_public_key)
        witness_stack.append(dil_sig)
    #After, we append the script
    witness_stack.append(revealed_script)
    #NOW, we execute everything on the witness stack in order
    #Process script processes all the opcodes in the script
    #In the process script function, we also confirm the tweak
    validation = process_script(msg, scriptPubKey)
    if(validation):
        return validation
    else:
        raise ValidationError("Signature and Public Key do not match")


def main():
    rpc_url = 'http://joshuageorgedai:333777000@127.0.0.1:18443/wallet/myaddress'
    proxy = RawProxy(service_url=rpc_url)

    #Schnorr keys generated as number (private key)
    #Or coordinate (public key)
    schnorr_private_key, schnorr_public_key = dsa.gen_keys()

    #Dilithum keys generated as byte strings
    dil_public_key, dil_private_key = dilithium.Dilithium2.keygen()

    #Generate new taproot address
    address = proxy.getnewaddress("", "bech32m")

    #Fund address 50 bitcoin
    fund(proxy, address, 1)

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
    #Generate witness and run validation for the witness
    if(witness_verification(proxy, 1, schnorr_public_key, dil_public_key, schnorr_private_key, dil_private_key, script_path_bool, script_path_schnorr, script_path_dil, scriptPubKey)):
        if (script_path_bool):
            print("Schnorr signature validation successful!")
        else:
            print("Dilithium signature validation successful!")


if __name__ == "__main__":
    main()