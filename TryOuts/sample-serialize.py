import os
import json
import struct

def serialize_coinbase_transaction(coinbase_data):
    # Parse JSON coinbase data
    coinbase_json = json.loads(coinbase_data)

    # Create coinbase transaction
    version = struct.pack("<I", coinbase_json["version"])  # 4 bytes, little-endian
    input_count = encode_varint(len(coinbase_json["vin"]))  # Variable-length encoding for input count
    input_data = b""  # Coinbase input data is empty for generation transaction
    output_count = encode_varint(len(coinbase_json["vout"]))  # Variable-length encoding for output count
    output_data = b""  # Output data is empty for generation transaction
    locktime = struct.pack("<I", coinbase_json["locktime"])  # 4 bytes, little-endian

    # Concatenate all parts of the transaction
    coinbase_transaction = version + input_count + input_data + output_count + output_data + locktime
    return coinbase_transaction.hex()

def encode_varint(value):
    if value < 0xFD:
        return struct.pack("<B", value)
    elif value <= 0xFFFF:
        return b"\xFD" + struct.pack("<H", value)
    elif value <= 0xFFFFFFFF:
        return b"\xFE" + struct.pack("<I", value)
    else:
        return b"\xFF" + struct.pack("<Q", value)

def serialize_coinbase_transactions_in_folder(folder_path):
    # Initialize an empty list to store serialized transactions
    serialized_transactions = []

    # Iterate over JSON files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, "r") as file: 
                coinbase_data = file.read()
                serialized_transaction = serialize_coinbase_transaction(coinbase_data)
                serialized_transactions.append(serialized_transaction)

    # Write all serialized transactions to a single file
    output_file_path = "TryOuts/sample-serialize.txt"
    with open(output_file_path, "w") as output_file:
        for serialized_transaction in serialized_transactions:
            output_file.write(serialized_transaction + "\n")
    print(f"All serialized transactions written to {output_file_path}")

# Provide the path to the folder containing JSON files
folder_path = "mempool"

# Serialize coinbase transactions in the folder and write to a single file
serialize_coinbase_transactions_in_folder(folder_path)
