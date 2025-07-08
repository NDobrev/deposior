from eth2deposit.deposit import DepositData
from eth2deposit.utils.crypto import SHA256
from py_ecc.bls import G2ProofOfPossession as bls

def make_withdrawal_credentials(eth1_address):
    return bytes.fromhex('01' + '00'*11 + eth1_address.lower().replace('0x',''))

def main():
    import sys
    import json
    if len(sys.argv) != 6:
        sys.exit("Usage: script.py <pubkey_hex> <eth1_address> <amount_gwei> <keystore_path> <password>")
    
    pubkey_hex, eth1_address, amount_gwei_str, keystore_path, password = sys.argv[1:]
    pubkey = bytes.fromhex(pubkey_hex)
    withdrawal_credentials = make_withdrawal_credentials(eth1_address)

    # decrypt private key (your existing decrypt_keystore function)
    privkey_bytes = decrypt_keystore(keystore_path, password)
    privkey = int.from_bytes(privkey_bytes, 'big')

    amount = int(amount_gwei_str)

    deposit_data = DepositData(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount,
        signature=b''  # placeholder initially
    )

    signing_root = deposit_data.signing_root
    signature = bls.Sign(privkey, signing_root)

    deposit_data.signature = signature

    deposit_json = {
        "pubkey": f"0x{pubkey.hex()}",
        "withdrawal_credentials": f"0x{withdrawal_credentials.hex()}",
        "amount": amount,
        "signature": f"0x{signature.hex()}",
        "deposit_message_root": f"0x{deposit_data.signing_root.hex()}",
        "deposit_data_root": f"0x{deposit_data.hash_tree_root.hex()}"
    }

    with open("deposit.json", "w") as f:
        json.dump(deposit_json, f, indent=4)

    print("Correct deposit JSON file generated: deposit.json")

if __name__ == "__main__":
    main()