import json
from typing import Optional

from web3 import Web3
from eth_account import Account
from py_ecc.bls import G2ProofOfPossession as bls

import deposit as dep

# Deposit contract constants
DEPOSIT_CONTRACT_ADDRESS = Web3.to_checksum_address("0x00000000219ab540356cBB839Cbe05303d7705Fa")
DEPOSIT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes", "name": "pubkey", "type": "bytes"},
            {"internalType": "bytes", "name": "withdrawal_credentials", "type": "bytes"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
            {"internalType": "bytes32", "name": "deposit_data_root", "type": "bytes32"},
        ],
        "name": "deposit",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    }
]


def generate_deposit(
    pubkey_hex: Optional[str],
    eth1_address: str,
    amount_gwei: int,
    keystore_path: str,
    password: str,
    output_file: Optional[str] = None,
) -> dict:
    """Create deposit JSON data from validator pubkey/keystore.

    If ``pubkey_hex`` is ``None`` the public key will be derived from the
    keystore's private key.
    """
    privkey_bytes = dep.decrypt_keystore(keystore_path, password)
    if len(privkey_bytes) != 32:
        raise ValueError("Decrypted private key must be exactly 32 bytes")
    privkey = int.from_bytes(privkey_bytes, "big")

    if pubkey_hex:
        pubkey = dep.hex_to_bytes(pubkey_hex, expected_len=48, field_name="pubkey")
    else:
        pubkey = bls.SkToPk(privkey)

    withdrawal_credentials = dep.make_withdrawal_credentials(eth1_address)

    deposit_message_root = dep.compute_deposit_message_root(
        pubkey, withdrawal_credentials, amount_gwei
    )
    signing_root = dep.sha256(deposit_message_root + dep.compute_deposit_domain())
    signature = bls.Sign(privkey, signing_root)
    deposit_data_root = dep.compute_deposit_data_root(
        pubkey, withdrawal_credentials, amount_gwei, signature
    )

    deposit_json = {
        "pubkey": f"0x{pubkey.hex()}",
        "withdrawal_credentials": f"0x{withdrawal_credentials.hex()}",
        "amount": amount_gwei,
        "signature": f"0x{signature.hex()}",
        "deposit_message_root": f"0x{deposit_message_root.hex()}",
        "deposit_data_root": f"0x{deposit_data_root.hex()}",
    }

    if output_file:
        with open(output_file, "w") as f:
            json.dump(deposit_json, f, indent=4)

    return deposit_json


def parse_deposit_data(deposit: dict) -> dict:
    """Parse deposit JSON dictionary and return binary values."""
    return {
        "pubkey": dep.hex_to_bytes(deposit["pubkey"], 48, "pubkey"),
        "withdrawal_credentials": dep.hex_to_bytes(
            deposit["withdrawal_credentials"], 32, "withdrawal_credentials"
        ),
        "amount": int(deposit["amount"]),
        "signature": dep.hex_to_bytes(deposit["signature"], 96, "signature"),
        "deposit_data_root": dep.hex_to_bytes(
            deposit["deposit_data_root"], 32, "deposit_data_root"
        ),
    }


def send_deposit(
    privkey: str, deposit: dict, eth_rpc_url: str = "https://rpc.hoodi.ethpandaops.io"
) -> str:
    """Send deposit transaction to the network and return tx hash."""
    w3 = Web3(Web3.HTTPProvider(eth_rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to Ethereum node: {eth_rpc_url}")

    account = Account.from_key(privkey)
    deposit_data = parse_deposit_data(deposit)

    contract = w3.eth.contract(address=DEPOSIT_CONTRACT_ADDRESS, abi=DEPOSIT_ABI)
    nonce = w3.eth.get_transaction_count(account.address)
    value = deposit_data["amount"] * 10**9

    txn = contract.functions.deposit(
        deposit_data["pubkey"],
        deposit_data["withdrawal_credentials"],
        deposit_data["signature"],
        deposit_data["deposit_data_root"],
    ).build_transaction(
        {
            "from": account.address,
            "value": value,
            "nonce": nonce,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )

    txn["gas"] = w3.eth.estimate_gas(txn)
    signed_txn = account.sign_transaction(txn)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return tx_hash.hex()
