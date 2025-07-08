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
from web3 import Web3
from eth_account import Account
from py_ecc.bls import G2ProofOfPossession as bls
import deposit_utils

# Configuration
CHAIN_NAME = 'hoodi'
CHAIN_ID = 560048
RPC_URL = 'https://rpc.hoodi.ethpandaops.io'
WALLETS_FILE = os.path.expanduser('~/.hoodi_wallets.json')

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
    return [{'address': w['address']} for w in wallets]

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
    pubkey: str = Form(...),
    withdrawal: str = Form(...),
    amount: int = Form(...),
    keystore: UploadFile = Form(...),
    password: str = Form(...),
):
    """Generate deposit JSON from uploaded keystore."""
    path = f"/tmp/{keystore.filename}"
    with open(path, 'wb') as f:
        f.write(await keystore.read())
    data = deposit_utils.generate_deposit(pubkey, withdrawal, amount, path, password)
    os.remove(path)
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
        tx_hash = deposit_utils.send_deposit(wallet['privateKey'], req.deposit)
        return DepositResponse(tx_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class KeystoreRequest(BaseModel):
    index: int = 0
    num_validators: int = 1
    mnemonic: Optional[str] = None
    chain: str = 'hoodi'
    output_dir: str = 'validator_keys'


@app.post('/generate_keystore')
async def api_generate_keystore(req: KeystoreRequest):
    cmd = ['nimbus_cli']
    if req.mnemonic:
        cmd += [
            'existing-mnemonic',
            '--validator_start_index', str(req.index),
            '--num_validators', str(req.num_validators),
            '--chain', req.chain,
        ]
    else:
        cmd += [
            'new-mnemonic',
            '--validator_start_index', str(req.index),
            '--num_validators', str(req.num_validators),
            '--chain', req.chain,
        ]
    cmd += ['--output_dir', req.output_dir]
    try:
        subprocess.run(cmd, check=True)
        return {'output_dir': req.output_dir}
    except subprocess.CalledProcessError as e:
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
