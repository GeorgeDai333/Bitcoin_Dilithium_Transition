# !/usr/bin/env python3
# !pip install ecdsa
# !pip install btclib
# !pip install python-bitcoinlib
# !pip install bitcoinlib

from bitcoin.rpc import RawProxy
from btclib.ecc.ssa import sign, verify
from btclib.ecc import dsa
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import hashlib
import struct
import binascii
from dilithium_py import dilithium


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

def msg_hash(proxy, amount_spent: float, schnorr_public_key, dil_public_key):
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
    print(f"Fake transaction: {transaction_decoded}")
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
    script = (
        b'\x63' +  # OP_IF
        struct.pack('B', len(x_only_pubkey)) + x_only_pubkey +  # Push 32 bytes
        b'\xac' +  # OP_CHECKSIG
        b'\x64' +  # OP_ELSE
        b'\xfd\x20\x05' + dil_public_key +  # Push 1312 bytes (varint + data)
        b'\xc0' +  # OP_CHECKDILITHIUMSIG (hypothetical opcode bit)
        b'\x68'  # OP_ENDIF
    )
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

    
    #We hard code our script used by the hybrid wallet
    script = f"OP_IF\n{schnorr_public_key} OP_CHECKSIG\nOP_ELSE\n{dil_public_key} OP_CHECKDILITHIUMSIG\nOP_ENDIF"

    #TODO: Phase 2 would need a new way of calculating scriptPubKey,
    # as we can't just tweak the public key anymore bcs Dilithium2 pub keys are too long

    #TODO: In phase 2, ANY public key checked by OP_CHECKSIG is permanently blacklisted


if __name__ == "__main__":
    main()