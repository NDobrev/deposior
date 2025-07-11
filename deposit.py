import sys
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from py_ecc.bls import G2ProofOfPossession as bls

DOMAIN_DEPOSIT = bytes.fromhex("03000000")
GENESIS_FORK_VERSION = bytes(4)

def compute_deposit_domain() -> bytes:
    """Return the deposit domain as used in the deposit contract"""
    return DOMAIN_DEPOSIT + GENESIS_FORK_VERSION + bytes(24)


def merkleize(chunks):
    """Merkleize a list of 32-byte chunks as defined in the spec."""
    import math
    if not chunks:
        return sha256(bytes(32))
    count = len(chunks)
    size = 1 << math.ceil(math.log2(count))
    chunks = list(chunks) + [bytes(32)] * (size - count)
    while len(chunks) > 1:
        chunks = [sha256(chunks[i] + chunks[i + 1]) for i in range(0, len(chunks), 2)]
    return chunks[0]


def compute_deposit_message_root(pubkey: bytes, withdrawal_credentials: bytes, amount: int) -> bytes:
    amount_le = int_to_bytes_le(amount, 8)
    packed = pubkey + withdrawal_credentials + amount_le + bytes(24)
    chunks = [packed[i:i + 32] for i in range(0, len(packed), 32)]
    return merkleize(chunks)


def compute_deposit_data_root(pubkey: bytes, withdrawal_credentials: bytes, amount: int, signature: bytes) -> bytes:
    amount_le = int_to_bytes_le(amount, 8)
    pubkey_root = sha256(pubkey + bytes(16))
    left = sha256(pubkey_root + withdrawal_credentials)
    sig_root = sha256(
        sha256(signature[:64]) +
        sha256(signature[64:] + bytes(32))
    )
    right = sha256(amount_le + bytes(24) + sig_root)
    return sha256(left + right)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hex_to_bytes(hex_str: str, expected_len=None, field_name="") -> bytes:
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    b = bytes.fromhex(hex_str)
    if expected_len and len(b) != expected_len:
        sys.exit(f"Invalid length for {field_name}: expected {expected_len} bytes, got {len(b)} bytes.")
    return b


def int_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, 'little')


def make_withdrawal_credentials(eth1_address: str) -> bytes:
    eth1_bytes = hex_to_bytes(eth1_address, expected_len=20, field_name="ETH1 withdrawal address")
    prefix = bytes([0x01])
    padding = bytes(11)  # 11 bytes padding + 1 prefix byte + 20 bytes address = 32 bytes total
    return prefix + padding + eth1_bytes


def decrypt_keystore(keystore_path: str, password: str) -> bytes:
    with open(keystore_path, "r") as f:
        keystore = json.load(f)

    crypto = keystore.get('crypto')
    if not crypto:
        sys.exit("Invalid keystore: missing crypto field")

    kdf = crypto.get('kdf')
    if not kdf or kdf.get('function') != 'pbkdf2':
        sys.exit("Unsupported KDF: only pbkdf2 supported")

    kdfparams = kdf.get('params')
    salt = hex_to_bytes(kdfparams.get('salt'))
    c = kdfparams.get('c')
    dklen = kdfparams.get('dklen')

    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, c, dklen)

    cipher = crypto.get('cipher')
    if not cipher or cipher.get('function') != 'aes-128-ctr':
        sys.exit("Unsupported cipher: only aes-128-ctr supported")

    ciphertext = hex_to_bytes(cipher.get('message'))
    iv = hex_to_bytes(cipher.get('params').get('iv'))

    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    aes = AES.new(derived_key[:16], AES.MODE_CTR, counter=ctr)
    decrypted = aes.decrypt(ciphertext)

    checksum = crypto.get('checksum')
    if not checksum or checksum.get('function') != 'sha256':
        sys.exit("Unsupported checksum function: only sha256 supported")

    mac_expected = hex_to_bytes(checksum.get('message'))
    mac_calculated = sha256(derived_key[16:32] + ciphertext)

    if mac_expected != mac_calculated:
        sys.exit("MAC check failed — wrong password or corrupted keystore")

    return decrypted


def main():
    if len(sys.argv) != 6:
        sys.exit("Usage: python generate_eth2_deposit.py <pubkey_hex_96chars> <eth1_withdrawal_address> <amount_gwei> <keystore_path> <keystore_password>")

    pubkey_hex, eth1_address, amount_gwei_str, keystore_path, password = sys.argv[1:6]

    pubkey = hex_to_bytes(pubkey_hex, expected_len=48, field_name="pubkey")

    withdrawal_credentials = make_withdrawal_credentials(eth1_address)

    privkey_bytes = decrypt_keystore(keystore_path, password)
    if len(privkey_bytes) != 32:
        sys.exit("Decrypted private key must be exactly 32 bytes")

    privkey = int.from_bytes(privkey_bytes, byteorder='big')

    try:
        amount = int(amount_gwei_str)
        if not (0 < amount <= 32000000000):  # Typically 32 ETH in gwei for deposit
            raise ValueError()
    except ValueError:
        sys.exit("Amount must be a positive integer in gwei, typically 32000000000 (32 ETH)")

    deposit_message_root = compute_deposit_message_root(pubkey, withdrawal_credentials, amount)
    signing_root = sha256(deposit_message_root + compute_deposit_domain())

    signature = bls.Sign(privkey, signing_root)
    deposit_data_root = compute_deposit_data_root(pubkey, withdrawal_credentials, amount, signature)

    deposit_json = {
        "pubkey": f"0x{pubkey.hex()}",
        "withdrawal_credentials": f"0x{withdrawal_credentials.hex()}",
        "amount": amount,
        "signature": f"0x{signature.hex()}",
        "deposit_message_root": f"0x{deposit_message_root.hex()}",
        "deposit_data_root": f"0x{deposit_data_root.hex()}"
    }

    with open("deposit.json", "w") as f:
        json.dump(deposit_json, f, indent=4)

    print("Deposit JSON file generated successfully: deposit.json")


if __name__ == "__main__":
    main()