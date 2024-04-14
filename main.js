const fs = require('fs');
const crypto = require('crypto');

class TransactionValidator {
    constructor(mempoolDir) {
        this.mempoolDir = mempoolDir;
        this.utxoSet = new Set(); // Simulated UTXO set
    }

    loadTransactionData(filename) {
        const fileContent = fs.readFileSync(filename, 'utf8');
        return JSON.parse(fileContent);
    }

    validateTransactionStructure(txData) {
        const requiredFields = ["version", "locktime", "vin", "vout"];
        return requiredFields.every(field => txData.hasOwnProperty(field));
    }

    validateInputs(txData) {
        for (const vin of txData.vin) {
            if (!this.utxoSet.has(vin.txid)) {
                console.log(`Input validation failed for transaction ${txData.txid}: Previous transaction output not found in UTXO set.`);
                return false;
            }
        }
        return true;
    }

    validateSignatures(txData) {
        for (const vin of txData.vin) {
            // Simulate signature verification
            if (vin.scriptsig !== "" && vin.scriptsig !== "valid_signature") {
                console.log(`Signature validation failed for transaction ${txData.txid}: Invalid signature.`);
                return false;
            }
        }
        return true;
    }

    validateScripts(txData) {
        for (const vin of txData.vin) {
            if (!vin.scriptsig.includes("valid_script_keyword")) {
                console.log(`Script validation failed for transaction ${txData.txid}: Invalid script.`);
                return false;
            }
        }
        return true;
    }

    checkDoubleSpending(txData) {
        const inputs = new Set(txData.vin.map(vin => vin.txid));
        if (inputs.size !== txData.vin.length) {
            console.log(`Double spending detected for transaction ${txData.txid}: Duplicate transaction inputs found.`);
            return true;
        }
        return false;
    }

    validateTransactions() {
        const validTransactions = [];
        console.log("Starting transaction validation process...\n");
        const files = fs.readdirSync(this.mempoolDir);
        for (const filename of files) {
            if (filename.endsWith(".json")) {
                const txData = this.loadTransactionData(`${this.mempoolDir}/${filename}`);
                const txid = txData.txid;
                console.log(`Validating transaction: ${txid}`);

                // Transaction Structure Validation
                if (!this.validateTransactionStructure(txData)) {
                    console.log(`Transaction structure validation failed for: ${txid}`);
                    continue;
                }

                // Input Validation
                if (!this.validateInputs(txData)) {
                    continue;
                }

                // Signature Validation
                if (!this.validateSignatures(txData)) {
                    continue;
                }

                // Script Validation
                if (!this.validateScripts(txData)) {
                    continue;
                }

                // Double Spending Check
                if (this.checkDoubleSpending(txData)) {
                    continue;
                }

                // If all validations passed, add to the list of valid transactions
                validTransactions.push(txid);
                console.log(`Transaction ${txid} successfully validated!\n`);
            }
        }
        return validTransactions;
    }
}

function generateBlockHeader(difficultyTarget) {
    // Generate a block header (for demonstration purpose, a simple hash of current time is used)
    const timestamp = Date.now().toString();
    let blockHeader = crypto.createHash('sha256').update(timestamp).digest('hex');
    // Add difficulty target to the block header
    blockHeader += difficultyTarget;
    return blockHeader;
}

function generateCoinbaseTransaction() {
    // Generate a serialized coinbase transaction (for demonstration purpose, a simple string is used)
    const coinbaseTx = "Coinbase transaction";
    return coinbaseTx;
}

function generateOutputFile(blockHeader, coinbaseTx, validTransactions) {
    let content = `${blockHeader}\n${coinbaseTx}\n`;
    for (const txid of validTransactions) {
        content += `${txid}\n`;
    }
    fs.writeFileSync("output.txt", content);
}

function main() {
    const difficultyTarget = "0000ffff00000000000000000000000000000000000000000000000000000000";

    // Initialize TransactionValidator with the mempool directory
    const validator = new TransactionValidator("mempool");

    // Set up the simulated UTXO set (for demonstration purpose, it's left empty)
    validator.utxoSet = new Set();

    // Validate transactions in the mempool directory
    const validTransactions = validator.validateTransactions();

    // Generate block header, coinbase transaction, and output file
    const blockHeader = generateBlockHeader(difficultyTarget);
    const coinbaseTx = generateCoinbaseTransaction();
    generateOutputFile(blockHeader, coinbaseTx, validTransactions);
}

main();
