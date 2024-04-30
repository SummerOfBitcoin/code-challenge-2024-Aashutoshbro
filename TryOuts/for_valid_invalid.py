import os
import json

def validate_transaction(transaction):
    # Validate the version
    if "version" not in transaction or transaction["version"] != 1:
        return False
    
    # Validate the locktime
    if "locktime" not in transaction or transaction["locktime"] != 0:
        return False
    
    # Validate the vin
    if "vin" not in transaction or not transaction["vin"]:
        return False
    
    # Validate the vout
    if "vout" not in transaction or not transaction["vout"]:
        return False
    
    # Validate each input in vin
    for vin in transaction["vin"]:
        # Validate txid
        if "txid" not in vin:
            return False
        
        # Validate vout
        if "vout" not in vin or not isinstance(vin["vout"], int):
            return False
        
        # Validate prevout
        if "prevout" not in vin:
            return False
        
        prevout = vin["prevout"]
        # Validate scriptpubkey
        if "scriptpubkey" not in prevout:
            return False
        
        # Validate value
        if "value" not in prevout or not isinstance(prevout["value"], int):
            return False
        
    # Validate each output in vout
    for vout in transaction["vout"]:
        # Validate scriptpubkey
        if "scriptpubkey" not in vout:
            return False
        
        # Validate value
        if "value" not in vout or not isinstance(vout["value"], int):
            return False
    
    return True

def validate_transactions_in_folder(folder_path):
    valid_transactions = []
    invalid_transactions = []
    
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, "r") as file:
                try:
                    transaction = json.load(file)
                    if validate_transaction(transaction):
                        valid_transactions.append(filename)
                    else:
                        invalid_transactions.append(filename)
                except json.JSONDecodeError:
                    invalid_transactions.append(filename)
    
    return valid_transactions, invalid_transactions

# Validate transactions in the mempool folder
valid_transactions, invalid_transactions = validate_transactions_in_folder("mempool")

# Write valid transactions to valid.txt
with open("TryOuts/for_valid.txt", "w") as valid_file:
    for filename in valid_transactions:
        valid_file.write(filename + "\n")

# Write invalid transactions to invalid.txt
with open("TryOuts/for_invalid.txt", "w") as invalid_file:
    for filename in invalid_transactions:
        invalid_file.write(filename + "\n")

print("Valid transactions written to valid.txt")
print("Invalid transactions written to invalid.txt")
