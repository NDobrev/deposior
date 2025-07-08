#!/usr/bin/env python3
"""
hoodi_tools.py
A unified CLI + REST service for Hoodi Testnet:
- Generate/manage EOA wallets
- Query balances
- Generate BLS validator keys
- Derive Eth2 keystores using Nimbus deposit CLI (nimbus_cli)
- Submit on-chain deposits for validators

Dependencies:
  pip install fastapi uvicorn web3 eth-account click py_ecc
"""
import os
import json
import secrets
import subprocess
import click
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from mnemonic import Mnemonic
from eth2deposit.key_handling.key_derivation.path import mnemonic_and_path_to_key
from web3 import Web3
from eth_account import Account
from py_ecc.bls import G2ProofOfPossession as bls
import deposit as dep
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib
import uuid

# Configuration
CHAIN_NAME = 'hoodi'
CHAIN_ID = 560048
RPC_URL = 'https://rpc.hoodi.ethpandaops.io'
WALLETS_FILE = os.path.expanduser('~/.hoodi_wallets.json')

# Directory for persisting deposit information
DATA_DIR = os.path.expanduser('~/depositor_persistant')
DB_FILE = os.path.join(DATA_DIR, 'db.json')

# Initialize Web3 provider
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Ensure eth-account HD features
Account.enable_unaudited_hdwallet_features()

# --- Deposit contract setup ---
DEPOSIT_CONTRACT_ADDRESS = w3.to_checksum_address('0x00000000219ab540356cBB839Cbe05303d7705Fa')  # Hoodi Testnet deposit contract
DEPOSIT_CONTRACT_ABI = [
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

# --- Persistence ---
def load_wallets():
    try:
        with open(WALLETS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_wallets(wallets):
    os.makedirs(os.path.dirname(WALLETS_FILE), exist_ok=True)
    with open(WALLETS_FILE, 'w') as f:
        json.dump(wallets, f, indent=2)


# --- Keystore deposit database helpers ---
def load_db():
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'used_keystores': {}}


def save_db(db):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

# --- Key generation ---
def generate_wallet():
    acct = Account.create()
    return {
        'address': acct.address,
        'privateKey': acct.key.hex(),
        'mnemonic': ''
    }


def generate_wallet_with_mnemonic():
    acct, mnemonic = Account.create_with_mnemonic()
    return {
        'address': acct.address,
        'privateKey': acct.key.hex(),
        'mnemonic': mnemonic
    }


# --- Deposit helpers (using deposit.py) ---
def create_keystore(privkey_bytes: bytes, password: str, path: str) -> None:
    """Create a minimal EIP-2335 keystore file at path."""
    salt = secrets.token_bytes(16)
    c = 262144
    dklen = 32
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, c, dklen)
    iv = secrets.token_bytes(16)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
    aes = AES.new(derived_key[:16], AES.MODE_CTR, counter=ctr)
    ciphertext = aes.encrypt(privkey_bytes)
    mac = hashlib.sha256(derived_key[16:32] + ciphertext).digest()
    keystore = {
        'crypto': {
            'kdf': {
                'function': 'pbkdf2',
                'params': {'dklen': dklen, 'salt': salt.hex(), 'c': c},
            },
            'checksum': {'function': 'sha256', 'params': {}, 'message': mac.hex()},
            'cipher': {
                'function': 'aes-128-ctr',
                'params': {'iv': iv.hex()},
                'message': ciphertext.hex(),
            },
        }
    }
    with open(path, 'w') as f:
        json.dump(keystore, f)


def generate_keystore(privkey_bytes: bytes, password: str, pubkey_hex: str,
                      derivation_path: str, path: str) -> dict:
    """Generate a full EIP-2335 keystore and write secret file.

    Returns the keystore dictionary.
    """
    salt = secrets.token_bytes(32)
    dklen = 32
    c = 1
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, c, dklen)
    iv = secrets.token_bytes(16)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
    aes = AES.new(derived_key[:16], AES.MODE_CTR, counter=ctr)
    ciphertext = aes.encrypt(privkey_bytes)
    mac = hashlib.sha256(derived_key[16:32] + ciphertext).digest()
    keystore = {
        'crypto': {
            'kdf': {
                'function': 'pbkdf2',
                'params': {
                    'dklen': dklen,
                    'c': c,
                    'prf': 'hmac-sha256',
                    'salt': salt.hex(),
                },
                'message': ''
            },
            'checksum': {'function': 'sha256', 'params': {}, 'message': mac.hex()},
            'cipher': {
                'function': 'aes-128-ctr',
                'params': {'iv': iv.hex()},
                'message': ciphertext.hex(),
            }
        },
        'pubkey': pubkey_hex,
        'path': derivation_path,
        'uuid': str(uuid.uuid4()),
        'version': 4,
    }

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(keystore, f, indent=4)

    os.makedirs('secrets', exist_ok=True)
    secret_path = os.path.join('secrets', pubkey_hex)
    with open(secret_path, 'w') as sf:
        sf.write(privkey_bytes.hex())

    return keystore


def generate_deposit(pubkey_hex: Optional[str], withdrawal: str, amount: int, keystore_path: str, password: str) -> dict:
    """Generate deposit data from a keystore.

    If ``pubkey_hex`` is ``None`` the validator public key is derived from the
    decrypted private key.
    """
    privkey_bytes = dep.decrypt_keystore(keystore_path, password)
    privkey = int.from_bytes(privkey_bytes, 'big')

    if pubkey_hex:
        pubkey = dep.hex_to_bytes(pubkey_hex, 48, 'pubkey')
    else:
        pubkey = bls.SkToPk(privkey)

    withdrawal_credentials = dep.make_withdrawal_credentials(withdrawal)
    msg_root = dep.compute_deposit_message_root(pubkey, withdrawal_credentials, amount)
    signing_root = dep.sha256(msg_root + dep.compute_deposit_domain())
    signature = bls.Sign(privkey, signing_root)
    data_root = dep.compute_deposit_data_root(pubkey, withdrawal_credentials, amount, signature)
    return {
        'pubkey': f'0x{pubkey.hex()}',
        'withdrawal_credentials': f'0x{withdrawal_credentials.hex()}',
        'amount': amount,
        'signature': f'0x{signature.hex()}',
        'deposit_message_root': f'0x{msg_root.hex()}',
        'deposit_data_root': f'0x{data_root.hex()}',
    }


def _parse_deposit(deposit: dict) -> dict:
    return {
        'pubkey': dep.hex_to_bytes(deposit['pubkey'], 48, 'pubkey'),
        'withdrawal_credentials': dep.hex_to_bytes(deposit['withdrawal_credentials'], 32, 'withdrawal_credentials'),
        'amount': int(deposit['amount']),
        'signature': dep.hex_to_bytes(deposit['signature'], 96, 'signature'),
        'deposit_data_root': dep.hex_to_bytes(deposit['deposit_data_root'], 32, 'deposit_data_root'),
    }


def send_deposit(privkey: str, deposit: dict, eth_rpc_url: str = RPC_URL) -> str:
    w3_local = Web3(Web3.HTTPProvider(eth_rpc_url))
    if not w3_local.is_connected():
        raise RuntimeError(f'Cannot connect to Ethereum node: {eth_rpc_url}')
    account = Account.from_key(privkey)
    d = _parse_deposit(deposit)
    contract = w3_local.eth.contract(address=DEPOSIT_CONTRACT_ADDRESS, abi=DEPOSIT_CONTRACT_ABI)
    nonce = w3_local.eth.get_transaction_count(account.address)
    value = d['amount'] * 10**9
    txn = contract.functions.deposit(
        d['pubkey'], d['withdrawal_credentials'], d['signature'], d['deposit_data_root']
    ).build_transaction({
        'from': account.address,
        'value': value,
        'nonce': nonce,
        'gasPrice': w3_local.eth.gas_price,
        'chainId': w3_local.eth.chain_id,
    })
    txn['gas'] = w3_local.eth.estimate_gas(txn)
    signed = account.sign_transaction(txn)
    tx_hash = w3_local.eth.send_raw_transaction(signed.rawTransaction)
    return tx_hash.hex()


def generate_validator_keys():
    sk = secrets.randbelow(bls.curve_order)
    pk = bls.SkToPk(sk)
    return {
        'validatorPrivateKey': hex(sk),
        'validatorPublicKey': pk.hex()
    }

# --- REST API ---
app = FastAPI(title="Hoodi Tools API")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def ui_index():
    return FileResponse("static/index.html")


@app.get('/keystores_page')
async def ui_keystores():
    """UI page for managing existing keystores."""
    return FileResponse("static/keystores.html")

@app.get('/wallet')
async def api_create_wallet():
    wallet = generate_wallet_with_mnemonic()
    wallets = load_wallets()
    wallets.append(wallet)
    save_wallets(wallets)
    return wallet

@app.get('/wallets')
async def api_list_wallets():
    wallets = load_wallets()
    result = []
    for w in wallets:
        try:
            bal = w3.eth.get_balance(w['address'])
            bal_eth = w3.from_wei(bal, 'ether')
            result.append({'address': w['address'], 'balance': str(bal_eth)})
        except Exception:
            result.append({'address': w['address'], 'balance': 'error'})
    return result

@app.get('/balance/{address}')
async def api_balance(address: str):
    if not w3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    try:
        bal = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(bal, 'ether')
        return {'address': address, 'balance': str(balance_eth)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/validator')
async def api_validator():
    return generate_validator_keys()


class DepositResponse(BaseModel):
    tx_hash: str


@app.post('/generate_deposit')
async def api_generate_deposit(
    pubkey: Optional[str] = Form(None),
    withdrawal: str = Form(...),
    amount: int = Form(...),
    keystore: Optional[UploadFile] = Form(None),
    password: str = Form(...),
    keystore_path: Optional[str] = Form(None),
):
    """Generate deposit JSON from uploaded keystore or server path."""
    if keystore is not None:
        path = f"/tmp/{keystore.filename}"
        with open(path, 'wb') as f:
            f.write(await keystore.read())
        data = generate_deposit(pubkey, withdrawal, amount, path, password)
        os.remove(path)
    elif keystore_path:
        data = generate_deposit(pubkey, withdrawal, amount, keystore_path, password)
    else:
        raise HTTPException(status_code=400, detail='Keystore file or path required')
    return data


class SendDepositRequest(BaseModel):
    address: str
    deposit: dict


@app.post('/send_deposit')
async def api_send_deposit(req: SendDepositRequest):
    wallets = load_wallets()
    wallet = next((w for w in wallets if Web3.to_checksum_address(w['address']) == Web3.to_checksum_address(req.address)), None)
    if wallet is None:
        raise HTTPException(status_code=404, detail='Wallet not found')
    try:
        tx_hash = send_deposit(wallet['privateKey'], req.deposit)
        return DepositResponse(tx_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class AutoDepositRequest(BaseModel):
    address: str
    password: str = 'password'
    amount: int = 32000000000


@app.post('/auto_deposit')
async def api_auto_deposit(req: AutoDepositRequest):
    """Run full deposit workflow for a wallet and return log messages."""
    wallets = load_wallets()
    wallet = next((w for w in wallets if Web3.to_checksum_address(w['address']) == Web3.to_checksum_address(req.address)), None)
    if wallet is None:
        raise HTTPException(status_code=404, detail='Wallet not found')

    logs = []
    try:
        logs.append('Generating validator keys')
        keys = generate_validator_keys()
        priv_bytes = int(keys['validatorPrivateKey'], 16).to_bytes(32, 'big')
        ks_path = f"/tmp/{keys['validatorPublicKey']}.json"
        create_keystore(priv_bytes, req.password, ks_path)
        logs.append(f'Keystore created: {ks_path}')
        deposit = generate_deposit(keys['validatorPublicKey'], wallet['address'], req.amount, ks_path, req.password)
        logs.append('Deposit data generated')
        tx_hash = send_deposit(wallet['privateKey'], deposit)
        logs.append(f'Transaction sent: {tx_hash}')
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        logs.append(f'Confirmed in block {receipt.blockNumber}')
        try:
            os.remove(ks_path)
        except FileNotFoundError:
            pass
        receipt_json = json.loads(Web3.to_json(receipt))
        return {'logs': logs, 'deposit': deposit, 'tx_hash': tx_hash, 'receipt': receipt_json}
    except Exception as e:
        logs.append(f'Error: {e}')
        return {'logs': logs, 'error': str(e)}


class KeystoreRequest(BaseModel):
    index: int = 0
    num_validators: int = 1
    mnemonic: Optional[str] = None
    chain: str = 'hoodi'
    output_dir: str = 'validator_keys'


@app.post('/generate_keystore')
async def api_generate_keystore(req: KeystoreRequest):
    os.makedirs(req.output_dir, exist_ok=True)
    mnemo = Mnemonic('english')
    mnemonic = req.mnemonic.strip() if req.mnemonic else ''
    if not mnemonic:
        mnemonic = mnemo.generate(256)
    keystore_file = None
    pubkey = None
    for i in range(req.num_validators):
        idx = req.index + i
        path = f"m/12381/3600/{idx}/0/0"
        sk = mnemonic_and_path_to_key(mnemonic=mnemonic, path=path, password='')
        sk_bytes = sk.to_bytes(32, 'big')
        pk_hex = bls.SkToPk(sk).hex()
        dir_path = os.path.join(req.output_dir, f"validator_{idx}")
        os.makedirs(dir_path, exist_ok=True)
        ks_path = os.path.join(dir_path, 'keystore.json')
        generate_keystore(sk_bytes, 'password', pk_hex, path, ks_path)
        if keystore_file is None:
            keystore_file = ks_path
            pubkey = pk_hex
    resp = {'output_dir': req.output_dir, 'mnemonic': mnemonic}
    if keystore_file:
        resp['keystore'] = keystore_file
    if pubkey:
        resp['pubkey'] = pubkey
    return resp


class ListKeystoresResponse(BaseModel):
    path: str
    used: bool
    tx_hash: Optional[str] = None


@app.get('/list_keystores')
async def api_list_keystores(path: str):
    """Return keystore files under the given directory with usage status."""
    result = []
    db = load_db()
    used = db.get('used_keystores', {})
    for root_dir, _, files in os.walk(path):
        for f in files:
            if f.endswith('keystore.json') or f == 'keystore.json':
                full = os.path.join(root_dir, f)
                tx = used.get(full)
                result.append({'path': full, 'used': tx is not None, 'tx_hash': tx})
    return result


class KeystoreDepositRequest(BaseModel):
    address: str
    keystore_path: str
    password: str = 'password'
    amount: int = 32000000000


@app.post('/deposit_keystore')
async def api_deposit_keystore(req: KeystoreDepositRequest):
    """Create deposit data from keystore and send transaction."""
    wallets = load_wallets()
    wallet = next((w for w in wallets if Web3.to_checksum_address(w['address']) == Web3.to_checksum_address(req.address)), None)
    if wallet is None:
        raise HTTPException(status_code=404, detail='Wallet not found')

    db = load_db()
    used = db.get('used_keystores', {})
    if req.keystore_path in used:
        return {'tx_hash': used[req.keystore_path], 'already_used': True}

    try:
        deposit = generate_deposit(None, wallet['address'], req.amount, req.keystore_path, req.password)
        tx_hash = send_deposit(wallet['privateKey'], deposit)
        used[req.keystore_path] = tx_hash
        db['used_keystores'] = used
        save_db(db)
        return {'tx_hash': tx_hash, 'deposit': deposit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- CLI ---
@click.group()
def cli():
    """CLI for Hoodi Testnet key management, address book, REST server, Eth2 keystore derivation, and deposits"""
    pass

@cli.command()
@click.option('--mnemonic/--no-mnemonic', default=True, help='Include mnemonic in generated wallet')
def wallet(mnemonic):
    """Generate EOA wallet, save to address book, optionally include mnemonic, and print JSON"""
    if mnemonic:
        w = generate_wallet_with_mnemonic()
    else:
        w = generate_wallet()
    wallets = load_wallets()
    wallets.append(w)
    save_wallets(wallets)
    click.echo(json.dumps(w, indent=2))

@cli.command('list-wallets')
def list_wallets():
    """List saved wallet addresses"""
    wallets = load_wallets()
    click.echo(json.dumps([w['address'] for w in wallets], indent=2))

@cli.command()
@click.argument('address')
def balance(address):
    """Get ETH balance for an address"""
    if not w3.is_address(address):
        click.echo('Error: Invalid address')
        return
    bal = w3.eth.get_balance(address)
    balance_eth = w3.from_wei(bal, 'ether')
    click.echo(json.dumps({'address': address, 'balance': str(balance_eth)}, indent=2))

@cli.command()
def validator():
    """Generate BLS validator key-pair and print as JSON"""
    click.echo(json.dumps(generate_validator_keys(), indent=2))

@cli.command()
@click.option('--index', '-i', default=0, help='Validator start index')
@click.option('--num-validators', '-n', default=1, help='Number of validators to generate')
@click.option('--mnemonic', '-m', default=None, help='Existing mnemonic for key derivation (omit to generate a new one)')
@click.option('--chain', '-c', default='hoodi', help='Chain name (default: hoodi)')
@click.option('--output-dir', '-o', default='validator_keys', help='Output directory for keystores')
def keystore(index, num_validators, mnemonic, chain, output_dir):
    """Generate Eth2 keystores using Nimbus deposit CLI (nimbus_cli).
    If --mnemonic is omitted, a new random mnemonic will be generated by nimbus_cli."""
    cmd = ['nimbus_cli']
    if mnemonic:
        cmd += ['existing-mnemonic',
                '--validator_start_index', str(index),
                '--num_validators', str(num_validators),
                '--chain', chain]
    else:
        cmd += ['new-mnemonic',
                '--validator_start_index', str(index),
                '--num_validators', str(num_validators),
                '--chain', chain]
    cmd += ['--output_dir', output_dir]
    click.echo(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        click.echo(f'Keystores generated in {output_dir}')
    except subprocess.CalledProcessError as e:
        click.echo(f'Error generating keystores: {e}', err=True)

@cli.command('deposit')
@click.argument('deposit_data_file', type=click.Path(exists=True))
@click.option('--sender', '-f', required=True, help='EOA address sending the deposit')
@click.option('--privkey', '-k', required=True, help='Private key of sender for signing')
@click.option('--gas-price', '-g', default=None, type=float, help='Gas price in gwei')
def deposit(deposit_data_file, sender, privkey, gas_price):
    """Submit a 32 ETH deposit to the Hoodi deposit contract"""
    try:
        with open(deposit_data_file, 'r') as f:
            dep = json.load(f)
        # parse hex fields
        pubkey = bytes.fromhex(dep['pubkey'][2:] if dep['pubkey'].startswith('0x') else dep['pubkey'])
        withdrawal_credentials = bytes.fromhex(dep['withdrawal_credentials'][2:] if dep['withdrawal_credentials'].startswith('0x') else dep['withdrawal_credentials'])
        signature = bytes.fromhex(dep['signature'][2:] if dep['signature'].startswith('0x') else dep['signature'])
        data_root = bytes.fromhex(dep['deposit_data_root'][2:] if dep['deposit_data_root'].startswith('0x') else dep['deposit_data_root'])
        # prepare contract
        contract = w3.eth.contract(address=DEPOSIT_CONTRACT_ADDRESS, abi=DEPOSIT_CONTRACT_ABI)
        nonce = w3.eth.get_transaction_count(sender)
        tx = contract.functions.deposit(pubkey, withdrawal_credentials, signature, data_root).buildTransaction({
            'from': sender,
            'value': w3.toWei(32, 'ether'),
            'nonce': nonce,
            'gas': 2000000
        })
        if gas_price:
            tx['gasPrice'] = w3.toWei(gas_price, 'gwei')
        signed = w3.eth.account.sign_transaction(tx, privkey)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        click.echo(f'Deposit tx sent: {tx_hash.hex()}')
    except Exception as e:
        click.echo(f'Error submitting deposit: {e}', err=True)

# Entry
if __name__ == '__main__':
    cli()
