import os
import json
import hashlib
import time

# Function to calculate Merkle root (dummy implementation)
def calculate_merkle_root(transactions):
    return hashlib.sha256(b'Merkle Root').hexdigest()

# Function to convert integer to little-endian byte representation
def int_to_little_endian(integer):
    hex_representation = hex(integer)[2:]  # Get hexadecimal representation
    if len(hex_representation) % 2 != 0:
        hex_representation = '0' + hex_representation  # Pad with zero if necessary
    little_endian_hex = ''.join(reversed([hex_representation[i:i+2] for i in range(0, len(hex_representation), 2)]))  # Convert to little-endian
    little_endian_bytes = bytes.fromhex(little_endian_hex)  # Convert to bytes
    return little_endian_bytes

# Function to generate block header
def generate_block_header(json_data):
    # Extract relevant information
    version = json_data['version']
    version_little_endian = int_to_little_endian(version)  # Convert version to little-endian
    previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder for previous block hash
    transactions = json_data['vin'] + json_data['vout']
    merkle_root = calculate_merkle_root(transactions)
    timestamp = int(time.time())
    timestamp_hex = hex(timestamp)[2:].zfill(8)  # Convert timestamp to hex with padding
    difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    nonce = 12345  # Example nonce value
    nonce_hex = hex(nonce)[2:].zfill(8)  # Convert nonce to hex with padding
    
    # Construct block header
    block_header = f"{version_little_endian.hex()}000000{previous_block_hash}{merkle_root}{timestamp_hex}{difficulty_target}{nonce_hex}"
    
    # Hash the block header
    block_hash = hashlib.sha256(block_header.encode()).hexdigest()
    
    return block_header, block_hash

# Directory containing JSON files
mempool_dir = "mempool"

# Output file for block headers
output_file = "TryOuts/serialize-extract-txids.txt"

# Open output file in write mode
with open(output_file, 'w') as f:
    # Iterate over JSON files in mempool directory
    for filename in os.listdir(mempool_dir):
        if filename.endswith(".json"):
            # Read JSON file
            with open(os.path.join(mempool_dir, filename)) as json_file:
                json_data = json.load(json_file)
            
            # Perform validation (**Add your transaction validation logic here**)**
            is_valid = True  # Placeholder for validation result
            
            if is_valid:
                # Generate block header for current JSON file
                block_header, block_hash = generate_block_header(json_data)
                
                # Write block header and hash to output file
                f.write(block_header + "\n")
                f.write("Block Hash:\n")
                f.write(block_hash + "\n\n")
