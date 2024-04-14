const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Function to calculate the block hash
function calculateBlockHash(blockHeader) {
    const blockHeaderBin = Buffer.from(blockHeader, 'hex');
    const blockHash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(blockHeaderBin).digest()).digest();
    return blockHash.reverse().toString('hex');
}

// Function to validate a transaction
function validateTransaction(transaction) {
    try {
        const vin = transaction.vin || [];
        const vout = transaction.vout || [];
        
        // Validate each input (vin)
        for (const input of vin) {
            const prevout = input.prevout || {};
            const scriptpubkeyType = prevout.scriptpubkey_type || '';
            const scriptpubkeyAddress = prevout.scriptpubkey_address || '';
            const value = prevout.value || 0;
            
            // Perform basic checks on input
            if (!['v0_p2wpkh', 'v1_p2tr'].includes(scriptpubkeyType)) {
                return false;
            }
            if (!scriptpubkeyAddress.startsWith('bc1')) {
                return false;
            }
            if (value <= 0) {
                return false;
            }
        }
        
        // Validate each output (vout)
        for (const output of vout) {
            const scriptpubkeyType = output.scriptpubkey_type || '';
            const scriptpubkeyAddress = output.scriptpubkey_address || '';
            const value = output.value || 0;
            
            // Perform basic checks on output
            if (!['v0_p2wpkh', 'v1_p2tr'].includes(scriptpubkeyType)) {
                return false;
            }
            if (!scriptpubkeyAddress.startsWith('bc1')) {
                return false;
            }
            if (value <= 0) {
                return false;
            }
        }
        
        return true;  // Transaction is valid if all checks pass
    } catch (error) {
        console.log(`Error validating transaction: ${error}`);
        return false;
    }
}

// Function to mine a block
function mineBlock(transactions, prevBlockHash, difficultyTarget) {
    let nonce = 0;
    while (true) {
        const blockHeader = prevBlockHash + nonce.toString(16).padStart(8, '0');
        const blockHash = calculateBlockHash(blockHeader);
        
        if (BigInt('0x' + blockHash) < BigInt('0x' + difficultyTarget)) {
            const validTransactions = transactions.filter(validateTransaction);
            if (validTransactions.length === 0) {
                throw new Error('No valid transactions to mine.');
            }
            
            const coinbaseTransaction = validTransactions[0];
            const txidList = validTransactions.map(tx => tx.vin[0].txid);
            
            return { blockHeader, blockHash, coinbaseTransaction, txidList };
        }
        
        nonce++;
    }
}

// Function to read transaction files from mempool folder
function readTransactionsFromMempool(mempoolDir) {
    const transactions = [];
    const files = fs.readdirSync(mempoolDir);
    for (const filename of files) {
        if (filename.endsWith('.json')) {
            const fileContent = fs.readFileSync(path.join(mempoolDir, filename), 'utf8');
            const transactionData = JSON.parse(fileContent);
            transactions.push(transactionData);
        }
    }
    console.log(`Number of transactions read: ${transactions.length}`);
    return transactions;
}

// Main function
function main() {
    const mempoolDir = './mempool';
    const difficultyTarget = '0000ffff00000000000000000000000000000000000000000000000000000000';
    const prevBlockHash = '0000000000000000000000000000000000000000000000000000000000000000';
    
    try {
        const transactions = readTransactionsFromMempool(mempoolDir);
        
        const { blockHeader, blockHash, coinbaseTransaction, txidList } = mineBlock(transactions, prevBlockHash, difficultyTarget);
        
        // Write block header, coinbase transaction, and transaction IDs to output file
        const outputFileContent = `${blockHeader}\n${JSON.stringify(coinbaseTransaction)}\n${txidList.join('\n')}\n`;
        fs.writeFileSync('output.txt', outputFileContent, 'utf8');
    } catch (error) {
        console.log(`An error occurred: ${error}`);
        process.exit(1);
    }
}

main();
