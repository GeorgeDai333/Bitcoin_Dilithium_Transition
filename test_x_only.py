from ecdsa import SigningKey, SECP256k1
import pandas as pd

def generate_schnorr_pubkeys(num_keys=5):
    data = []
    for _ in range(num_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        pubkey_point = vk.pubkey.point
        x = int(pubkey_point.x())
        y = int(pubkey_point.y())
        x_only_pubkey = x.to_bytes(32, 'big')
        data.append({
            'Public Key (X)': x,
            'Public Key (Y)': y,
            'X-only PubKey (hex)': x_only_pubkey
        })

    return pd.DataFrame(data)

# Generate 5 test cases
test_cases_df = generate_schnorr_pubkeys(5)
print(test_cases_df.to_string(index=False))