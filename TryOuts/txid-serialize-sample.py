import os
import json

def validate_transaction(transaction_data):
    # Parse the transaction JSON data
    transaction = json.loads(transaction_data)

    # Validate the transaction
    if "version" not in transaction or \
       "locktime" not in transaction or \
       "vin" not in transaction or \
       "vout" not in transaction:
        # Missing required fields
        return False

    # Validate version and locktime
    if not isinstance(transaction["version"], int) or \
       not isinstance(transaction["locktime"], int):
        # Version and locktime should be integers
        return False

    # Validate inputs
    for vin in transaction["vin"]:
        if "txid" not in vin or \
           "vout" not in vin or \
           "sequence" not in vin:
            # Missing required fields in input
            return False
        if not isinstance(vin["txid"], str) or \
           not isinstance(vin["vout"], int) or \
           not isinstance(vin["sequence"], int):
            # txid should be string, vout and sequence should be integers
            return False

    # Validate outputs
    for vout in transaction["vout"]:
        if "scriptpubkey" not in vout or \
           "value" not in vout:
            # Missing required fields in output
            return False
        if not isinstance(vout["scriptpubkey"], str) or \
           not isinstance(vout["value"], int):
            # scriptpubkey should be string, value should be integer
            return False

    # All validation checks passed, transaction is valid
    return True

def serialize_coinbase_transaction(transaction_data):
    coinbase_json = json.loads(transaction_data)
    input_count = encode_varint(len(coinbase_json["vin"]))  # Variable-length encoding for input count
    # Serialize transaction data
    serialized_transaction = input_count

    for vin in coinbase_json["vin"]:
        serialized_transaction += bytes.fromhex(vin["txid"])
        serialized_transaction += vin["vout"].to_bytes(4, byteorder="little")  # 4 bytes
        if "scriptpubkey" in vin:
            serialized_transaction += encode_varint(len(vin["scriptpubkey"])) + bytes.fromhex(vin["scriptpubkey"])  # Variable-length encoding for scriptpubkey length
        else:
            # If scriptpubkey is missing, add a placeholder byte
            serialized_transaction += bytes.fromhex("00")  # Placeholder byte
        serialized_transaction += vin["sequence"].to_bytes(4, byteorder="little")  # 4 bytes

    return serialized_transaction

def encode_varint(value):
    if value < 0xfd:
        return value.to_bytes(1, byteorder="little")
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, byteorder="little")
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, byteorder="little")
    else:
        return b'\xff' + value.to_bytes(8, byteorder="little")

def serialize_coinbase_transactions_in_folder(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, "r") as file:
                transaction_data = file.read()
                if validate_transaction(transaction_data):
                    serialized_transaction = serialize_coinbase_transaction(transaction_data)
                    with open("TryOuts/txid-serialize-sample.txt", "a") as output_file:
                        output_file.write(serialized_transaction.hex() + "\n")

# Example usage:
folder_path = "mempool"
serialize_coinbase_transactions_in_folder(folder_path)
