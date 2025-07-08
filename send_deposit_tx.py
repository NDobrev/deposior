import sys
import json
import os
import time
from web3 import Web3
from eth_account import Account

# Deposit contract address and minimal ABI
DEPOSIT_CONTRACT_ADDRESS = Web3.to_checksum_address("0x00000000219ab540356cBB839Cbe05303d7705Fa")
DEPOSIT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes", "name": "pubkey", "type": "bytes"},
            {"internalType": "bytes", "name": "withdrawal_credentials", "type": "bytes"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
            {"internalType": "bytes32", "name": "deposit_data_root", "type": "bytes32"}
        ],
        "name": "deposit",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    }
]

def load_wallets():
    path = os.path.expanduser("~/.hoodi_wallets.json")
    if not os.path.exists(path):
        sys.exit(f"Wallets file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)

def find_wallet(wallets, address):
    address = Web3.to_checksum_address(address)
    for w in wallets:
        if Web3.to_checksum_address(w['address']) == address:
            return w
    return None

def clean_hex(s, expected_len=None, field_name=""):
    s_clean = s[2:] if s.startswith("0x") else s
    b = bytes.fromhex(s_clean)
    if expected_len and len(b) != expected_len:
        sys.exit(f"Invalid length for {field_name}: expected {expected_len}, got {len(b)} bytes.")
    return b

def parse_deposit_json(filename):
    with open(filename, "r") as f:
        deposit = json.load(f)

    return {
        "pubkey": clean_hex(deposit["pubkey"], 48, "pubkey"),
        "withdrawal_credentials": clean_hex(deposit["withdrawal_credentials"], 32, "withdrawal_credentials"),
        "amount": int(deposit["amount"]),
        "signature": clean_hex(deposit["signature"], 96, "signature"),
        "deposit_data_root": clean_hex(deposit["deposit_data_root"], 32, "deposit_data_root")
    }

def wait_for_confirmation(w3, tx_hash, timeout=300, poll_interval=10):
    print(f"Waiting for transaction {tx_hash.hex()} confirmation...")
    start = time.time()
    while time.time() - start < timeout:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if receipt:
            if receipt.status == 1:
                print(f"Transaction confirmed in block {receipt.blockNumber}")
                return receipt
            else:
                sys.exit(f"Transaction failed in block {receipt.blockNumber}")
        time.sleep(poll_interval)
    sys.exit("Timeout waiting for transaction confirmation.")

def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python send_deposit_tx.py <wallet_address> <deposit_json_file>")

    wallet_address, deposit_file = sys.argv[1], sys.argv[2]

    wallets = load_wallets()
    wallet = find_wallet(wallets, wallet_address)
    if wallet is None:
        sys.exit(f"Wallet {wallet_address} not found in ~/.hoodi_wallets.json")

    privkey = wallet["privateKey"]
    account = Account.from_key(privkey)

    eth_rpc = os.getenv("ETH_RPC_URL", "https://rpc.hoodi.ethpandaops.io")
    w3 = Web3(Web3.HTTPProvider(eth_rpc))
    if not w3.is_connected():
        sys.exit(f"Cannot connect to Ethereum node: {eth_rpc}")

    deposit_data = parse_deposit_json(deposit_file)

    contract = w3.eth.contract(address=DEPOSIT_CONTRACT_ADDRESS, abi=DEPOSIT_ABI)

    nonce = w3.eth.get_transaction_count(account.address)

    value = deposit_data["amount"] * 10**9  # amount in gwei to wei

    txn = contract.functions.deposit(
        deposit_data["pubkey"],
        deposit_data["withdrawal_credentials"],
        deposit_data["signature"],
        deposit_data["deposit_data_root"]
    ).build_transaction({
        "from": account.address,
        "value": value,
        "nonce": nonce,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id
    })

    try:
        txn["gas"] = w3.eth.estimate_gas(txn)
        print(f"Estimated gas: {txn['gas']}")
    except Exception as e:
        sys.exit(f"Gas estimation failed: {e}")

    signed_txn = account.sign_transaction(txn)

    try:
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        print(f"Transaction sent with hash: {tx_hash.hex()}")
    except Exception as e:
        sys.exit(f"Failed to send transaction: {e}")

    wait_for_confirmation(w3, tx_hash)

if __name__ == "__main__":
    main()