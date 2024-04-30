import os
import json
import hashlib
import time

# Function to calculate Merkle root (dummy implementation)
def calculate_merkle_root(transactions):
    return hashlib.sha256(b'Merkle Root').hexdigest()

# Function to generate block header
def generate_block_header(json_data):
    # Extract relevant information
    version = json_data['version']
    previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder for previous block hash
    transactions = json_data['vin'] + json_data['vout']
    merkle_root = calculate_merkle_root(transactions)
    timestamp = int(time.time())
    difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    nonce = 12345  # Example nonce value
    
    # Construct block header
    block_header = f"Version: {version}\nPrevious Block Hash: {previous_block_hash}\nMerkle Root: {merkle_root}\nTimestamp: {timestamp}\nDifficulty Target: {difficulty_target}\nNonce: {nonce}"
    
    # Hash the block header
    block_hash = hashlib.sha256(block_header.encode()).hexdigest()
    
    return block_header, block_hash

# Directory containing JSON files
mempool_dir = "mempool"

# Output file for block headers
output_file = "TryOuts/block-sample.txt"

# Open output file in write mode
with open(output_file, 'w') as f:
    # Iterate over JSON files in mempool directory
    for filename in os.listdir(mempool_dir):
        if filename.endswith(".json"):
            # Read JSON file
            with open(os.path.join(mempool_dir, filename)) as json_file:
                json_data = json.load(json_file)
            
            # Perform validation (add your validation logic here)
            is_valid = True  # Placeholder for validation result
            
            if is_valid:
                # Generate block header for current JSON file
                block_header, block_hash = generate_block_header(json_data)
                
                # Write block header and hash to output file
                f.write("Block Header:\n")
                f.write(block_header + "\n")
                f.write("Block Hash:\n")
                f.write(block_hash + "\n\n")
