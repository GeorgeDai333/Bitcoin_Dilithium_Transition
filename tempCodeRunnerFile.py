    # unsafe_schnorr_public_key_new = bytes.fromhex(proxy.getaddressinfo(address_new)['witness_program'])
    # protocol_ID = b'\x43\x44\x52\x50'
    # version = 1
    # #Opreturn example for hybrid script
    # script_opreturn_hybrid_new = f"OP_RETURN {protocol_ID} {version} {int.from_bytes(hashlib.sha256(unsafe_schnorr_public_key_new + hashlib.sha256(tweak_pubkey([script_path_schnorr_new, script_path_dil_new])).digest()).digest())}"

    # #Commit unsafe public key
    # witness_opreturn(script_opreturn_hybrid_new)

    # #Fund address 50 bitcoin
    # #This mines 101 blocks, easily enough to confirm the op_return
    # fund(address_new, 1)

    # #Should succeed because of mined blocks
    # unsafe_schnorr_public_key_new = x_only_to_schnorr(unsafe_schnorr_public_key_new)
    # script_path_bool_new = True
    # print(witness_verification(1, unsafe_schnorr_public_key_new, dil_public_key_new, tweak_pubkey([script_path_schnorr_new, script_path_dil_new]), dil_private_key_new, script_path_bool_new, script_path_schnorr_new, script_path_dil_new, scriptPubKey_new))