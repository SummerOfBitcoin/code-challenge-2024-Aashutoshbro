import json
import os
import hashlib
import binascii
import bech32
from Crypto.Hash import RIPEMD160
from ecdsa import VerifyingKey, SECP256k1, util
import binascii
import struct
from typing import List
import time 

# Function to calculate the hash with the SHA-256 algorithm

# class S256Point: # sample code for reference
# ...
#  def hash160(self, compressed=True):
#  return hash160(self.sec(compressed))
#  def address(self, compressed=True, testnet=False):
#  '''Returns the address string'''
#  h160 = self.hash160(compressed)
#  if testnet:
#  prefix = b'\x6f'
#  else:
#  prefix = b'\x00'
#  return encode_base58_checksum(prefix + h160)



def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

# Constants for the Bitcoin protocol 
MEMPOOL_DIR = "mempool" 
TARGET_DIFFICULTY = "0000ffff00000000000000000000000000000000000000000000000000000000"
MAX_BLOCK_SIZE = 1000000

# Function to calculate hash with the SHA-256
def hash_txid_HexDG(txid):
    txid_bytes = bytes.fromhex(txid)
    # Calculate double SHA-256 hash
    hashed_txid = hashlib.sha256(txid_bytes).hexdigest()
    return hashed_txid

def validate_locktime_timestamp(transaction):
    # Get the current UNIX timestamp for comparison
    current_time = int(time.time())
    transaction_locktime = transaction['locktime']
    # Checks if the transaction locktime is a UNIX timestamp 
    if transaction_locktime >= 500000000: 
        # Validate the transaction based on the current time
        if current_time >= transaction_locktime:
            return True
        else:
            return False
    else:
        return True

# Function to validate the transaction fields from the mempool
def main_process_mempool():
    valid_transactions = []
    for filename in os.listdir(MEMPOOL_DIR):
        filepath = os.path.join(MEMPOOL_DIR, filename)
        with open(filepath, 'r') as file:
            transaction = json.load(file)
            # Validate the transaction fields
            if (validate_locktime_timestamp(transaction) and validate_transaction_field(transaction)):
                valid = 1
                for index,vin in enumerate(transaction['vin']):
                    try:
                        # Check the type of scriptPubKey and call the respective function
                        if vin["prevout"]["scriptpubkey_type"] == 'p2pkh': 
                            if not verify_p2pkh_transaction_in(vin,transaction,index): 
                                valid = 0
                                break
                        elif vin["prevout"]["scriptpubkey_type"] == 'v0_p2wpkh': 
                            if not verify_p2wpkh_transaction_in(vin,transaction,index): 
                                valid = 0
                                break
                        elif vin["prevout"]["scriptpubkey_type"] == 'v0_p2wsh': 
                            if not verify_p2wsh_tx(vin,transaction,index): 
                                valid = 0
                                break
                        elif vin["prevout"]["scriptpubkey_type"] == 'p2sh': 
                            if "witness" in vin:
                                if not verify_p2sh_p2wpkh_transaction(vin,transaction,index): 
                                    valid = 0
                                    break
                            else:
                                if not verify_p2sh_transaction(vin,transaction,index):
                                    valid = 0
                                    break
                        else:
                            continue
                    except Exception as e:
                        valid = 0
                        break
                if(valid): 
                    valid_transactions.append(transaction)        
    return valid_transactions # Return the list of valid transactions

# Function to validate the block fields and list of transactions 
def validate_transaction_field(transaction):
    essential_field = ['vin', 'vout']

    # Check for availability of essential fields
    for field in essential_field:
        # If the field is not present or empty in the transaction field, returns False
        if field not in transaction :
            return False

    # Check for the non-empty fields and If the transaction is SegWit, it should have a 'witness' field for each 'vin'
    for vin in transaction['vin']:
        # Additionally check that 'txid' and 'vout' are present and non-empty in each 'vin'
        if 'txid' not in vin:
            return False,
        if 'vout' not in vin : 
            return False,

    # 'vout' has a non-empty 'scriptPubKey' for the transaction
    for vout in transaction['vout']:
        if 'scriptPubKey' not in vout :
            return False,

    #Transaction includes all essential fields and they are non-empty.
    return True, 

# Function to check if the input value is greater than the output value
def checks_ip_greater_than_op(transaction):
    total_ip_value = 0
    total_op_value = 0
    for vin in transaction.get('vin'):
        total_ip_value += vin["prevout"]["value"]

    for vout in transaction.get('vout'):
        total_op_value += vout["value"]

    return total_ip_value >= total_op_value 

# Function to serialize an integer as a VarInt
def serialize_varINT(value): 
    if value < 0xfd:
        return value.to_bytes(1, byteorder='little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, byteorder='little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, byteorder='little')
    else:
        return b'\xff' + value.to_bytes(8, byteorder='little')

# Function to serialize the transaction using the format specified in the Bitcoin protocol
def serialize_tx(tx):
    serialized_tx_val = bytearray()

    # Version (little-endian) 
    serialized_tx_val.extend(int(tx['version']).to_bytes(4, byteorder='little'))

    # Number of inputs, using VarInt and serialized as little-endian 
    serialized_tx_val.extend(serialize_varINT(len(tx['vin'])))

    # Inputs for each input in the transaction
    for vin in tx['vin']: 
        # TXID (little-endian)
        serialized_tx_val.extend(bytes.fromhex(vin['txid'])[::-1])
        # VOUT (little-endian)
        serialized_tx_val.extend(int(vin['vout']).to_bytes(4, byteorder='little'))
        # ScriptSig length and ScriptSig for Seqeit inputs in txid calc
        serialized_tx_val.extend(serialize_varINT(len(bytes.fromhex(vin.get('scriptsig', '')))))
        if 'scriptsig' in vin:
            serialized_tx_val.extend(bytes.fromhex(vin['scriptsig']))
        # Sequence (little-endian) conversion
        serialized_tx_val.extend(int(vin['sequence']).to_bytes(4, byteorder='little'))

    # Number of outputs, using VarInt and serialized as little-endian
    serialized_tx_val.extend(serialize_varINT(len(tx['vout'])))

    # Outputs
    for vout in tx['vout']:
        # Value
        serialized_tx_val.extend(int(vout['value']).to_bytes(8, byteorder='little'))
        # ScriptPubKey length and ScriptPubKey, using VarInt for the length
        scriptpubkey_bytes = bytes.fromhex(vout['scriptpubkey'])
        # Append the length of the scriptPubKey to the serialized transaction
        serialized_tx_val.extend(serialize_varINT(len(scriptpubkey_bytes)))
        serialized_tx_val.extend(scriptpubkey_bytes)

    # Locktime using little endian
    serialized_tx_val.extend(int(tx['locktime']).to_bytes(4, byteorder='little'))
    # It returns the serialized transaction
    return bytes(serialized_tx_val)

# Function to calculate the double SHA-256 hash of the serialized transaction
def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

# Function to calculate the transaction ID from the serialized transaction
def get_txid(tx):
    serialized_tx_val = serialize_tx(tx)
    txid = double_sha256(serialized_tx_val)
    # Return the transaction ID in hexadecimal format and reverse txid to match usual big-endian hex display
    return txid[::-1].hex()

def serialize_legacy_tx_val(tx):
    serialized_tx_val = bytearray()

    # Version like above
    serialized_tx_val.extend(int(tx['version']).to_bytes(4, byteorder='little'))

    # Number of inputs, using VarInt and serialized as little-endian
    serialized_tx_val.extend(serialize_varINT(len(tx['vin'])))

    # For each input in the transaction (Inputs)
    for vin in tx['vin']:
        # It return the TXID in little-endian
        serialized_tx_val.extend(bytes.fromhex(vin['txid'])[::-1])
        # It return the VOUT in little-endian
        serialized_tx_val.extend(int(vin['vout']).to_bytes(4, byteorder='little'))
        # ScriptSig length and ScriptSig for Seqeit inputs in txid calc
        scriptsig_bytes = bytes.fromhex(vin['scriptsig'])
        serialized_tx_val.extend(serialize_varINT(len(scriptsig_bytes)))
        serialized_tx_val.extend(scriptsig_bytes)
        # For sequence in little-endian
        serialized_tx_val.extend(int(vin['sequence']).to_bytes(4, byteorder='little'))

    # Number of outputs, using VarInt and serialized as little-endian
    serialized_tx_val.extend(serialize_varINT(len(tx['vout'])))

    # For each output in the transaction (Onputs)
    for vout in tx['vout']:
        serialized_tx_val.extend(int(vout['value']).to_bytes(8, byteorder='little'))
        # ScriptPubKey length and ScriptPubKey, using VarInt for the length
        scriptpubkey_bytes = bytes.fromhex(vout['scriptpubkey'])
        # Append the length of the scriptPubKey to the serialized transaction
        serialized_tx_val.extend(serialize_varINT(len(scriptpubkey_bytes)))  
        serialized_tx_val.extend(scriptpubkey_bytes)

    # Locktime like above
    serialized_tx_val.extend(int(tx['locktime']).to_bytes(4, byteorder='little'))

    return bytes(serialized_tx_val)

# Function to calculate the reverse txid from the serialized transaction to match hex
def get_legacy_txid(tx):
    serialized_tx_val = serialize_legacy_tx_val(tx)
    txid = double_sha256(serialized_tx_val)             
    return txid[::-1].hex() 

def is_legacy_transaction(tx):
    # Checks if input has a 'witness' field, indicating SegWit usage in the transaction
    for vin in tx.get('vin', []):
        if 'witness' in vin:
            return False  # Not a legacy transaction if any input has 'witness'
    return True

def HASH160(pubkey_bytes): 
    # Calculate the SHA-256 hash of the public key
    sha256_pubkey = hashlib.sha256(pubkey_bytes).digest()
    return ripemd160(sha256_pubkey)

def verify_p2wpkh_transaction_in(vin,transaction,index):
    # Extract the witness data, scriptPubKey, and provided address from the transaction
    witness = vin['witness']
    scriptPubKey = vin['prevout']['scriptpubkey']
    provided_address = vin['prevout']['scriptpubkey_address']
    # Validate the number of items in the witness data
    if len(witness) != 2:
        return False # "Invalid number of items in witness data"

    signature, pubkey_hex = witness
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    # Validate the public key format if it is compressed and 33 bytes long and if transaction in invalid
    if not (pubkey_bytes[0] in [0x02, 0x03] and len(pubkey_bytes) == 33):
        # "Invalid public key format or length"
        return False

    # For HASH160
    ripemd160_pubkey_main = HASH160(pubkey_bytes)

    # Extract the pubkey hash from scriptPubKey, Assuming scriptPubKey structure for p2wpkh: 0x0014 <pubKeyHash>
    expected_pubkey_hash = scriptPubKey[4:]

    # Verify above HASH160(hash) matches the scriptPubKey pubkey hash extracted
    if ripemd160_pubkey_main.hex() != expected_pubkey_hash:
        return False

    # Placeholder for actual signature verification and making it readable form
    hrp = "bc" 
    witness_version = 0
    computed_bech32_address = bech32.encode(hrp, witness_version, ripemd160_pubkey_main)
    if computed_bech32_address != provided_address:
        return False
    
    is_signature_valid = False
    if(signature[-2:]) == "01":
        t = compute_sighash_p2wpkh(transaction,index,vin["prevout"]["value"])
        is_signature_valid = verify_signature(pubkey_hex,signature[:-2],t)
    return is_signature_valid # Return the result of the signature verification finally verified

# Function to decode a Base58Check address and return the payload
def base58check_decode(address):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' # Base58 alphabet
    decoded = 0
    # Decode the Base58Check address
    for char in address:
        decoded = decoded * 58 + alphabet.index(char)
    decoded_bytes = decoded.to_bytes(25, byteorder='big')
    checksum = decoded_bytes[-4:]
    payload = decoded_bytes[:-4]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum:
        # skips the version byte
        return payload[1:]
    else:
        raise ValueError("Invalid address checksum")

def hash256(data):
    # Calculate the double SHA-256 hash of the data
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# Function to compute the SIGHASH for a P2WPKH transaction
def compute_sighash_p2wpkh(transaction, input_index, input_amount):
    
    version = transaction['version'].to_bytes(4, byteorder='little')

    # Hashed TXID and VOUT pairs for all inputs
    txid_vout_pairs = b''.join(bytes.fromhex(vin['txid'])[::-1] + vin['vout'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashPrevOuts = hash256(txid_vout_pairs)

    sequences = b''.join(vin['sequence'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashSequence = hash256(sequences)

    # Outpoint for the input being spent (TXID and VOUT) 
    outpoint = bytes.fromhex(transaction['vin'][input_index]['txid'])[::-1] + transaction['vin'][input_index]['vout'].to_bytes(4, byteorder='little')

    # ScriptCode for P2WPKH is the HASH160 of the public key hash (P2PKH)
    pubkey_hash = transaction['vin'][input_index]['prevout']['scriptpubkey'][4:]
    scriptcode = bytes.fromhex('1976a914' + pubkey_hash + '88ac')

    value = input_amount.to_bytes(8, byteorder='little')

    sequence = transaction['vin'][input_index]['sequence'].to_bytes(4, byteorder='little')

    # Hashed outputs along with their values and scriptPubKeys
    serialized_outputs = b''.join(int(vout['value']).to_bytes(8, byteorder='little') + serialize_varINT(len(bytes.fromhex(vout['scriptpubkey']))) + bytes.fromhex(vout['scriptpubkey']) for vout in transaction['vout'])
    hashOutputs = hash256(serialized_outputs)

    locktime = transaction['locktime'].to_bytes(4, byteorder='little')

    # For SIGHASH_ALL
    if transaction["vin"][input_index]["witness"][0][-2:] == "01":
        sighashtype = (1).to_bytes(4, byteorder='little')
    else : 
        sighashtype = (0x81).to_bytes(4, byteorder='little') 

    # Combine for preimage
    preimage = version + hashPrevOuts + hashSequence + outpoint + scriptcode + value + sequence + hashOutputs + locktime + sighashtype
    # Hash preimage and return the hex digest
    sighash = hashlib.sha256(preimage).digest()

    return sighash.hex()

# Function to verify a P2PKH transaction
def verify_p2pkh_transaction_in(vin,transaction,index):
    scriptSig_hex = vin["scriptsig"] # Extract the scriptSig from the input
    scriptPubKey = vin['prevout']['scriptpubkey'] # Extract the scriptPubKey from the input
    provided_address = vin['prevout']['scriptpubkey_address'] # Extract the provided address from the input 

    # Extract the signature and public key from the scriptSig
    # Assuming scriptSig structure for p2pkh: <sig> <pubkey>
    sig_end = int(scriptSig_hex[:2], 16) * 2 + 2
    signature_hex = scriptSig_hex[2:sig_end]
    pubkey_hex = scriptSig_hex[sig_end+2:]
    
    # Convert the public key to bytes
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    # HASH160 of the public key
    ripemd160_pubkey_main = HASH160(pubkey_bytes)

    # Extract the pubkey hash from scriptPubKey, Assuming scriptPubKey structure for p2pkh: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    # Extract HASH160 from scriptPubKey for less time complexity
    expected_pubkey_hash = scriptPubKey[6:46]  

    # Verify the HASH160(pubkey) matches the scriptPubKey pubkey hash extracted 
    if ripemd160_pubkey_main.hex() != expected_pubkey_hash:
        return False  

    decoded_pubkey_hash = base58check_decode(provided_address)

    # Validate the decoded address hash against the computed HASH160(pubkey) matches computed ripemd160_pubkey_main
    if ripemd160_pubkey_main != decoded_pubkey_hash:
        return False

    # Verify the signature using the public key and the SIGHASH
    is_signature_valid = True
    if signature_hex[-2:] == '01':
        t = compute_sighash_all(transaction,index)
    elif signature_hex[-2:] == '81':
        t = compute_sighash_anyonecanpay_all(transaction,index)    
    is_signature_valid = verify_signature(pubkey_hex,signature_hex[:-2],t)
    return is_signature_valid

# Function to verify a P2SH transaction and combine the signatures
def compute_sighash_all(transaction, input_index):
    serialized_tx_val = transaction['version'].to_bytes(4, byteorder='little')
    serialized_tx_val += serialize_varINT(len(transaction['vin']))

    # Serialize all inputs first except the current input
    for i, vin in enumerate(transaction['vin']):
        txid = bytes.fromhex(vin['txid'])[::-1]
        vout = vin['vout'].to_bytes(4, byteorder='little')
        script = b''
        sequence = vin['sequence'].to_bytes(4, byteorder='little')
        if i == input_index:
            script = bytes.fromhex(vin['prevout']['scriptpubkey'])
        script_len = serialize_varINT(len(script))
        serialized_tx_val += txid + vout + script_len + script + sequence

    # Serialize all outputs first as in SIGHASH_ALL
    serialized_tx_val += serialize_varINT(len(transaction['vout']))
    for vout in transaction['vout']:
        value = int(vout['value']).to_bytes(8, byteorder='little')
        scriptpubkey = bytes.fromhex(vout['scriptpubkey'])
        scriptpubkey_len = serialize_varINT(len(scriptpubkey))
        serialized_tx_val += value + scriptpubkey_len + scriptpubkey

    # Append locktime and sighash type for SIGHASH_ALL
    serialized_tx_val += transaction['locktime'].to_bytes(4, byteorder='little')
    serialized_tx_val += (1).to_bytes(4, byteorder='little')  # SIGHASH_ALL
    sighash = hashlib.sha256(serialized_tx_val).digest()
    return sighash.hex()

# Function to compute the SIGHASH for a P2SH transaction with SIGHASH_ALL
def compute_sighash_anyonecanpay_all(transaction, input_index):
    serialized_tx_val = transaction['version'].to_bytes(4, byteorder='little')
    # Serialize only the current input and Only one input is considered at a time
    serialized_tx_val += serialize_varINT(1)

    # Serialize the current input except the scriptSig
    vin = transaction['vin'][input_index]
    txid = bytes.fromhex(vin['txid'])[::-1]
    vout = vin['vout'].to_bytes(4, byteorder='little')
    script = bytes.fromhex(vin['prevout']['scriptpubkey'])  # Script of the output being spent
    sequence = vin['sequence'].to_bytes(4, byteorder='little')
    script_len = serialize_varINT(len(script))
    serialized_tx_val += txid + vout + script_len + script + sequence

    # Serializing outputs
    serialized_tx_val += serialize_varINT(len(transaction['vout']))
    for vout in transaction['vout']:
        value = int(vout['value']).to_bytes(8, byteorder='little')
        scriptpubkey = bytes.fromhex(vout['scriptpubkey'])
        scriptpubkey_len = serialize_varINT(len(scriptpubkey))
        serialized_tx_val += value + scriptpubkey_len + scriptpubkey

    # Combine locktime and SIGHASH type for SIGHASH_ALL
    serialized_tx_val += transaction['locktime'].to_bytes(4, byteorder='little')
    serialized_tx_val += (0x81).to_bytes(4, byteorder='little')  # SIGHASH_ANYONECANPAY | SIGHASH_ALL

    sighash = hashlib.sha256(serialized_tx_val).digest()
    return sighash.hex()

def verify_signature(pubkey_hex, signature_der_hex, message_hex):
    # Decode the public key, signature, and message from hex
    pubkey_bytes = binascii.unhexlify(pubkey_hex)
    signature_der_bytes = binascii.unhexlify(signature_der_hex)
    message_hash_bytes = binascii.unhexlify(message_hex)  # Assuming this is the double SHA-256 hash

    # Create a VerifyingKey object from the public key
    vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)

    # Parse the DER-encoded signature to obtain the raw signature (r and s values) and verify the signature
    r, s = util.sigdecode_der(signature_der_bytes, vk.curve.order)

    # Convert r and s to the 64-byte signature format used by ecdsa library
    signature_bytes = util.sigencode_string(r, s, vk.curve.order)

    # Verify the signature against the message hash using the public key
    try:
        is_valid = vk.verify(signature_bytes, message_hash_bytes, hashfunc=util.sha256, sigdecode=util.sigdecode_string)
        return is_valid
    except Exception as e:
        return False

# Function to verify a P2SH transaction along with the signatures
def verify_p2sh_p2wpkh_transaction(vin,transaction,index):
    scriptSig = vin['scriptsig']
    scriptPubKey = vin['prevout']['scriptpubkey']
    witness = vin['witness']
    provided_address = vin['prevout']['scriptpubkey_address']

    # Using the last element of the scriptSig ASM as the redeem script for P2SH(P2WPKH)
    redeem_script_hex = vin['scriptsig_asm'].split(" ")[-1] 
    redeem_script = bytes.fromhex(redeem_script_hex)

    if len(redeem_script) > 520:
        return False

    # Validating redeem script hash against scriptPubKey and provided address form mempool
    redeem_script_hash = HASH160(redeem_script)
    # Extract the pubkey hash from scriptPubKey, Assuming scriptPubKey structure for p2sh: OP_HASH160 <hash> OP_EQUAL
    expected_script_hash = scriptPubKey[4:44]
    if redeem_script_hash.hex() != expected_script_hash:
        return False

    # Decode the provided address and validate it against the redeem script hash
    decoded_pubkey_hash = base58check_decode(provided_address)

    if redeem_script_hash.hex() != decoded_pubkey_hash.hex():
        return False

    # [<signature>, <pubkey>] as demonstrated in the witness field


    is_signature_valid = True
    if len(witness) == 2:
        signature_hex, pubkey_hex = witness
        t = compute_sighash_p2sh_p2wpkh(transaction,index,vin["prevout"]["value"])
        is_signature_valid = verify_signature(pubkey_hex,signature_hex[:-2],t)

        return is_signature_valid

    else :
        sig = []
        for i in witness[:-1] :
            if i != "":
                sig.append(i) # Extract the signatures from the witness field

        inner_witnessscript = vin["inner_witnessscript_asm"].split(" ")
        pub = []
        for i in range(len(inner_witnessscript)):
            if inner_witnessscript[i] == "OP_PUSHBYTES_33":
                pub.append(inner_witnessscript[i+1])
        t = compute_sighash_p2sh_p2wpkh_multi(transaction,index,vin["prevout"]["value"])
        j = 0
        for i in pub:
            if(verify_signature(i,sig[j][:-2],t)): 
                j+=1
            if(j==len(sig)):break 

    if(j==len(sig)): return True # Return True if all signatures are valid
    return False

# Function to compute the SIGHASH for a P2SH(P2WPKH) transaction
def compute_sighash_p2sh_p2wpkh_multi(transaction, input_index, input_amount):

    version = transaction['version'].to_bytes(4, byteorder='little')

    # Hashed TXID and VOUT pairs for all inputs
    txid_vout_pairs = b''.join(bytes.fromhex(vin['txid'])[::-1] + vin['vout'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashPrevOuts = hash256(txid_vout_pairs)

    sequences = b''.join(vin['sequence'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashSequence = hash256(sequences)

    # Outpoint for the input being spent (TXID and VOUT)
    outpoint = bytes.fromhex(transaction['vin'][input_index]['txid'])[::-1] + transaction['vin'][input_index]['vout'].to_bytes(4, byteorder='little')

    # ScriptCode for P2WPKH is the HASH160 of the public key hash (P2PKH)
    witness_script = bytes.fromhex(transaction['vin'][input_index]['witness'][-1])
    scriptcode = serialize_varINT(len(witness_script)) + witness_script

    value = input_amount.to_bytes(8, byteorder='little')

    sequence = transaction['vin'][input_index]['sequence'].to_bytes(4, byteorder='little')

    # Hashed outputs along with their values and scriptPubKeys
    serialized_outputs = b''.join(int(vout['value']).to_bytes(8, byteorder='little') + serialize_varINT(len(bytes.fromhex(vout['scriptpubkey']))) + bytes.fromhex(vout['scriptpubkey']) for vout in transaction['vout'])
    hashOutputs = hash256(serialized_outputs)

    locktime = transaction['locktime'].to_bytes(4, byteorder='little')

    # For SIGHASH_ALL
    sighashtype = (1).to_bytes(4, byteorder='little')

    # Combine preimage according to the format
    preimage = version + hashPrevOuts + hashSequence + outpoint + scriptcode + value + sequence + hashOutputs + locktime + sighashtype
    # Hash preimage and return the hex digest
    sighash = hashlib.sha256(preimage).digest()
    # Return the hex digest of the preimage
    return sighash.hex()

def compute_sighash_p2sh_p2wpkh(transaction, input_index, input_amount):
    
    version = transaction['version'].to_bytes(4, byteorder='little')

    # Hashed TXID and VOUT pairs for all inputs
    txid_vout_pairs = b''.join(bytes.fromhex(vin['txid'])[::-1] + vin['vout'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashPrevOuts = hash256(txid_vout_pairs)

    sequences = b''.join(vin['sequence'].to_bytes(4, byteorder='little') for vin in transaction['vin'])
    hashSequence = hash256(sequences)

    # Outpoint for the input being spent (TXID and VOUT)
    outpoint = bytes.fromhex(transaction['vin'][input_index]['txid'])[::-1] + transaction['vin'][input_index]['vout'].to_bytes(4, byteorder='little')

    # ScriptCode for P2WPKH is the HASH160 of the public key hash (P2PKH)
    pubkey_hash = transaction['vin'][input_index]['inner_redeemscript_asm'].split(" ")[-1]
    scriptcode = bytes.fromhex('1976a914' + pubkey_hash + '88ac')

    value = input_amount.to_bytes(8, byteorder='little')

    sequence = transaction['vin'][input_index]['sequence'].to_bytes(4, byteorder='little')

    # Hashed outputs along with their values and scriptPubKeys
    serialized_outputs = b''.join(int(vout['value']).to_bytes(8, byteorder='little') + serialize_varINT(len(bytes.fromhex(vout['scriptpubkey']))) + bytes.fromhex(vout['scriptpubkey']) for vout in transaction['vout'])
    hashOutputs = hash256(serialized_outputs)

    locktime = transaction['locktime'].to_bytes(4, byteorder='little')

    # For SIGHASH_ALL
    if transaction["vin"][input_index]["witness"][0][-2:] == "01":
        sighashtype = (1).to_bytes(4, byteorder='little')
    else : 
        sighashtype = (0x83).to_bytes(4, byteorder='little')  # SIGHASH_ANYONECANPAY | SIGHASH_ALL

    # Combine for preimage along 
    preimage = version + hashPrevOuts + hashSequence + outpoint + scriptcode + value + sequence + hashOutputs + locktime + sighashtype
    # Hash preimage and return the hex digest
    sighash = hashlib.sha256(preimage).digest()
    return sighash.hex()


# Function to verify a P2SH transaction
def verify_p2sh_transaction(vin,transaction,index):
    scriptSig = vin['scriptsig']
    scriptPubKey = vin['prevout']['scriptpubkey']
    provided_address = vin['prevout']['scriptpubkey_address']

    # Extract the redeem script from scriptSig for P2SH(P2WPKH)
    redeem_script_hex = vin['scriptsig_asm'].split(" ")[-1]
    redeem_script = bytes.fromhex(redeem_script_hex)

    if len(redeem_script) > 520:
        return False

    # validate redeem script hash against scriptPubKey and provided address form mempool  
    redeem_script_hash = HASH160(redeem_script)
    expected_script_hash = scriptPubKey[4:44]
    if redeem_script_hash.hex() != expected_script_hash:
        return False

    # Decode the provided address and validate it against the redeem script hash
    decoded_pubkey_hash = base58check_decode(provided_address)

    if redeem_script_hash.hex() != decoded_pubkey_hash.hex():
        return False

    t = compute_sighash_p2sh(transaction,index)
    sig = []
    components = vin["scriptsig_asm"].split(" ")[2:-2]
    for i in range(0,len(components),2):
        sig.append(components[i])

    pubkey = []
    components = vin["inner_redeemscript_asm"].split(" ")[2:-2]
    for i in range(0,len(components),2):
        pubkey.append(components[i])
    j = 0
    for i in pubkey:
       if(verify_signature(i,sig[j][:-2],t)): 
          j+=1
       if(j==len(sig)):break 

    if(j==len(sig)): return True
    return False

def compute_sighash_p2sh(transaction, input_index=-1):
    serialized = transaction['version'].to_bytes(4, byteorder='little')

    # analyze the inputs without the scriptSig for the current input
    serialized += len(transaction['vin']).to_bytes(1, byteorder='little')

    # Serializing inputs
    for index, input_item in enumerate(transaction['vin']):
    
        txid = bytes.fromhex(input_item['txid'])
        serialized += txid[::-1]
        # VOUT in little-endian
        vout = input_item['vout'].to_bytes(4, byteorder='little')
        serialized += vout

        if index == input_index or input_index == -1:
            scriptsig_asm = input_item.get('scriptsig_asm', '').split()
            redeem_script = scriptsig_asm[-1] if scriptsig_asm else ''
            redeem_script_bytes = bytes.fromhex(redeem_script)
            serialized += len(redeem_script_bytes).to_bytes(1, byteorder='little') + redeem_script_bytes
        else:
            serialized += b'\x00' 

        sequence = input_item['sequence'].to_bytes(4, byteorder='little')
        serialized += sequence
    # Serializing outputs
    serialized += len(transaction['vout']).to_bytes(1, byteorder='little')

    for output in transaction['vout']:
        value = output['value'].to_bytes(8, byteorder='little')
        serialized += value

        scriptpubkey = bytes.fromhex(output['scriptpubkey'])
        serialized += len(scriptpubkey).to_bytes(1, byteorder='little') + scriptpubkey

    locktime = transaction['locktime'].to_bytes(4, byteorder='little')
    serialized += locktime
    # SIGHASH_ALL for the signature hash type
    serialized += b'\x01\x00\x00\x00'
    sighash = hashlib.sha256(serialized).digest()
    return sighash.hex()

# Function to verify a P2WSH transaction
def verify_p2wsh_tx(vin,transaction,index):
    provided_scriptpubkey = vin['prevout']['scriptpubkey']
    provided_address = vin['prevout']['scriptpubkey_address']


    # Extract the SHA-256 hash from the provided scriptPubKey
    expected_sha256_hash = provided_scriptpubkey[4:]

    witness_script_asm = vin['witness']
    witness_script_bytes = witness_script_asm[-1] 
    witness_script_bytes = binascii.unhexlify(witness_script_bytes)
    calculated_sha256_hash = hashlib.sha256(witness_script_bytes).hexdigest()

    # Verify the calculated SHA-256 hash matches the expected hash
    if calculated_sha256_hash != expected_sha256_hash:
        return False

    # Actual verification of the signatures and the script
    script_hash_hex = expected_sha256_hash
    script_hash_bytes = bytes.fromhex(script_hash_hex)

    hrp = "bc"  
    witness_version = 0  
    computed_bech32_address = bech32.encode(hrp, witness_version, script_hash_bytes)

    # Comparing the computed bech32 address with the provided address from the mempool
    if computed_bech32_address != provided_address:
        return False
    witness = vin["witness"]
    sig = []
    for i in witness[:-1] :
        if i != "":
            sig.append(i)

    inner_witnessscript = vin["inner_witnessscript_asm"].split(" ")
    pub = []
    for i in range(len(inner_witnessscript)):
        if inner_witnessscript[i] == "OP_PUSHBYTES_33":
            pub.append(inner_witnessscript[i+1])
    t = compute_sighash_p2sh_p2wpkh_multi(transaction,index,vin["prevout"]["value"])
    j = 0
    for i in pub:
        if(verify_signature(i,sig[j][:-2],t)): 
            j+=1
        if(j==len(sig)):break 

    if(j==len(sig)): return True
    return False

# Function to classify transactions by the scriptPubKey type of the prevout
def calculate_transaction_weight(tx):
    non_witness_bytes = 0
    witness_bytes = 0

    tx_type = "SEGWIT" if any('witness' in vin for vin in tx['vin']) else "LEGACY"

    if tx_type == "LEGACY":

        non_witness_bytes += 4

        if len(tx['vin']) >= 50:
            raise ValueError("Many Inputs")

        non_witness_bytes += 1

        # Inputs for legacy transactions
        for input in tx['vin']:
            txid = bytes.fromhex(input['txid'])
            non_witness_bytes += 32

            non_witness_bytes += 4
            # ScriptSig length and ScriptSig
            script_sig = bytes.fromhex(input.get('scriptsig', ''))
            non_witness_bytes += 1 + len(script_sig)

            non_witness_bytes += 4

        if len(tx['vout']) >= 50:
            raise ValueError("Too many outputs")

        non_witness_bytes += 1
        # Outputs for legacy transactions
        for output in tx['vout']:
            non_witness_bytes += 8

            scriptpubkey = bytes.fromhex(output['scriptpubkey'])
            non_witness_bytes += 1 + len(scriptpubkey)
        non_witness_bytes += 4

    else:
        non_witness_bytes += 4

        witness_bytes += 2

        if len(tx['vin']) >= 50:
            raise ValueError("Too many inputs")

        non_witness_bytes += 1

        for input in tx['vin']:
            non_witness_bytes += 32 + 4

            script_sig = bytes.fromhex(input.get('scriptsig', ''))
            non_witness_bytes += 1 + len(script_sig)

            non_witness_bytes += 4

        if len(tx['vout']) >= 255:
            raise ValueError("Too many outputs")

        non_witness_bytes += 1

        for output in tx['vout']:
            non_witness_bytes += 8 + 1 + len(bytes.fromhex(output['scriptpubkey']))

        for input in tx['vin']:
            witness = input.get('witness', [])
            for item in witness:
                item_bytes = bytes.fromhex(item)
                witness_bytes += 1 + len(item_bytes)

        non_witness_bytes += 4

    # Calculate the transaction weight
    tx_weight = (non_witness_bytes * 4) + witness_bytes

    return tx_weight

# Function to classify transactions by the scriptPubKey type of the prevout
def cal_fees(transaction):
    total_ip_value = 0
    total_op_value = 0
    for vin in transaction.get('vin'):
        total_ip_value += vin["prevout"]["value"]

    for vout in transaction.get('vout'):
        total_op_value += vout["value"]

    return total_ip_value - total_op_value

# Function that returns the valid transactions
def best_transactions_for_block(valid_transactions):
    selected_transactions = []
    max_block_weight = 4000000 
    # Sort the transactions by fee and select the top 4k transactions
    amount = 0
    temp = []
    for transaction in valid_transactions:
        # Calculates the fees for the transaction
        fees = cal_fees(transaction)  
        # Store the fee in the transaction dictionary
        transaction['fees'] = fees
        temp.append(transaction)
    # Sort the transactions by the fee in descending order for maximum fees
    sorted_transactions = sorted(temp, key=lambda x: x['fees'], reverse=True)
    sorted_transactions = sorted_transactions[0:4000]
    # Calculate the total weight of the selected transactions
    for transaction in sorted_transactions:
            amount += transaction['fees']   
    return sorted_transactions,amount

# Function that returns id and wid with the valid transactions
def return_id(transactions):
    id = []
    wid = []
    for tx in transactions:
        if is_legacy_transaction(tx):
            id.append(get_legacy_txid(tx))
        else:
            id.append(get_txid(tx))
            wid.append(get_txid(tx))
    return id,wid

# Function that returns hashes of the valid transactions

# def merkle_root(txids: List[str]) -> str:
#     hashes = [bytes.fromhex(txid) for txid in txids]
#     while len(hashes) > 1:
#         if len(hashes) % 2 == 1:
#             hashes.append(hashes[-1])
#         new_hashes = []
#         for i in range(0, len(hashes), 2):
#             combined_hash = double_sha256(hashes[i] + hashes[i + 1])
#             new_hashes.append(combined_hash)
#         hashes = new_hashes
# #     return hashes[0].hexdigest()

# This is how we calculate the target given the bits field in Python:

# >>> from helper import little_endian_to_int
# >>> bits = bytes.fromhex('e93c0118')
# >>> exponent = bits[-1]
# >>> coefficient = little_endian_to_int(bits[:-1])
# >>> target = coefficient * 256**(exponent - 3)
# >>> print('{:x}'.format(target).zfill(64))
# 0000000000000000013ce9000000000000000000000000000000000000000000



def merkle_root(txids: List[str]) -> str:
    hashes = [bytes.fromhex(txid) for txid in txids]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [double_sha256(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0].hex()


# function for witness commitment for the block
def witness_commitment(txs):
    root = merkle_root(txs)
    reserved = '00' * 32  # 32 bytes of zero
    return double_sha256(bytes.fromhex(root + reserved)).hex()

# Function to create a coinbase transaction
def coinbase(txs):
    tx = bytearray()
    tx.extend(b'\x01\x00\x00\x00') # Version
    tx.extend(b'\x00') # Marker
    tx.extend(b'\x01') # Flag
    tx.extend(b'\x01') # Num Inputs
    tx.extend(b'\x00' * 32) # Prev Tx Hash
    tx.extend(b'\xff\xff\xff\xff') # Prev Txout Index
    tx.extend(b'\x00') # Txin Script Len
    tx.extend(b'\xff\xff\xff\xff') # Sequence
    tx.extend(b'\x02') # Num Outputs

    # First Output (Reward)
    tx.extend(bytes.fromhex('28a0d11500000000')) # Amount 1
    tx.extend(b'\x19') # Txout Script Len
    tx.extend(bytes.fromhex('76a914edf10a7fac6b32e24daa5305c723f3ee58db1bc888ac')) # ScriptPubKey

    # Second Output (Witness Commitment)
    tx.extend(bytes.fromhex('0000000000000000')) # Amount 2
    script = bytes.fromhex('6a24aa21a9ed') + bytes.fromhex(witness_commitment(txs))
    tx.extend(len(script).to_bytes(1, 'big')) # Txout Script Len
    tx.extend(script) # Script

    # Locktime (Current Block Height)
    tx.extend(b'\x01\x20') # Stack Items Len
    tx.extend(b'\x00' * 32)
    tx.extend(b'\x00\x00\x00\x00') # Locktime
    txid = double_sha256(tx)
    return tx.hex(), txid[::-1].hex()


# # Function to generate block header
# def generate_block_header(json_data):
#     # Extract relevant information
#     version = json_data['version']
#     previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder for previous block hash
#     transactions = json_data['vin'] + json_data['vout']
#     merkle_root = calculate_merkle_root(transactions)
#     timestamp = int(time.time())
#     difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
#     nonce = 12345  # Example nonce value
    
#     # Construct block header
#     block_header = f"Version: {version}\nPrevious Block Hash: {previous_block_hash}\nMerkle Root: {merkle_root}\nTimestamp: {timestamp}\nDifficulty Target: {difficulty_target}\nNonce: {nonce}"
    
#     # Hash the block header
#     block_hash = hashlib.sha256(block_header.encode()).hexdigest()
    
#     return block_header, block_hash


# Function to create a block header with the merkle root
def create_block_header(merkle_root):
    version = 0x20000000  # Version 00000020
    prev_block_hash = '64' + '00' * 31  # 32-byte value with 0x64 at the start
    prev_block_hash_bytes = bytes.fromhex(prev_block_hash)  # Already in little-endian form

    # Convert the given difficulty target into bits
    difficulty_target = '0000ffff00000000000000000000000000000000000000000000000000000000'
    bits = 0x1d00ffff  # Compact format of the difficulty target

    # remaining fields
    merkle_root_bytes = bytes.fromhex(merkle_root)[::-1]  # Reverse to match little-endian
    timestamp = int(time.time())
    timestamp_bytes = struct.pack('<I', timestamp)
    bits_bytes = struct.pack('<I', bits)

    nonce = 0
    target = int(difficulty_target, 16)
    target_bytes = target.to_bytes(32, byteorder='big')

    # Main mining loop to find the valid nonce value for the block header hash to be less than the target
    while True:
        nonce_bytes = struct.pack('<I', nonce)
        header = (struct.pack('<I', version) + prev_block_hash_bytes +
                  merkle_root_bytes + timestamp_bytes +
                  bits_bytes + nonce_bytes)
        block_hash = double_sha256(header)

        if block_hash[::-1] < target_bytes:
            break
        nonce += 1

    return header.hex()

BLOCK_HEIGHT = 840000
GRANT = 3.125 * 100000000

transactions = main_process_mempool()
best_transaction , amount = best_transactions_for_block(transactions)
amount += GRANT
amount = int(amount)
amount =  amount.to_bytes(8, byteorder='little').hex()
tx_id , wid = return_id(best_transaction)
coinbase_txn , coinbase_id = coinbase(wid)
tx_id.insert(0,coinbase_id)
root = merkle_root(tx_id)
block_header = create_block_header(root)
output_content = f"{block_header}\n{coinbase_txn}\n" + "\n".join(tx_id)

# Write the block header and transactions to the output file according to the given format
output_file_path = 'output.txt'
with open(output_file_path, 'w') as file:
    file.write(output_content)


# for version 
# class Tx:
#  def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
#  self.version = version
#  self.tx_ins = tx_ins
#  self.tx_outs = tx_outs
#  self.locktime = locktime
#  self.testnet = testnet
#  def __repr__(self):
#  tx_ins = ''
#  for tx_in in self.tx_ins:
#  tx_ins += tx_in.__repr__() + '\n'
#  tx_outs = ''
#  for tx_out in self.tx_outs:
#  tx_outs += tx_out.__repr__() + '\n'
#  return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
#  self.id(),
#  self.version,
#  tx_ins,
#  tx_outs,
#  self.locktime,
#  )
#  def id(self):
#  '''Human-readable hexadecimal of the transaction hash'''
#  return self.hash().hex()
#  def hash(self):
#  '''Binary hash of the legacy serialization'''
#  return hash256(self.serialize())[::-1]











# Two functions from helper.py will be used to parse and serialize varint fields:
# def read_varint(s):
#  '''read_varint reads a variable integer from a stream'''
#  i = s.read(1)[0]
#  if i == 0xfd:
#  # 0xfd means the next two bytes are the number
#  return little_endian_to_int(s.read(2))
#  elif i == 0xfe:
#  # 0xfe means the next four bytes are the number
#  return little_endian_to_int(s.read(4))
#  elif i == 0xff:
#  # 0xff means the next eight bytes are the number
#  return little_endian_to_int(s.read(8))
#  else:
#  # anything else is just the integer
#  return i
# def encode_varint(i):
#  '''encodes an integer as a varint'''
#  if i < 0xfd:
#  return bytes([i])
#  elif i < 0x10000:
#  return b'\xfd' + int_to_little_endian(i, 2)
#  elif i < 0x100000000:
#  return b'\xfe' + int_to_little_endian(i, 4)
#  elif i < 0x10000000000000000:
#  return b'\xff' + int_to_little_endian(i, 8)
#  else:
#  raise ValueError('integer too large: {}'.format(i))
