const fs = require('fs');
const crypto = require('crypto');

// Function to read transactions from the mempool folder
function readTransactionsFromMempool(mempoolDir) {
    const transactions = [];
    // Read all transaction files from the mempool folder
    const files = fs.readdirSync(mempoolDir);
    for (const file of files) {
        if (file.endsWith('.json')) {
            const filePath = `${mempoolDir}/${file}`;
            const transactionData = fs.readFileSync(filePath, 'utf8');
            const transaction = JSON.parse(transactionData);
            transactions.push(transaction);
        }
    }
    console.log(`Number of transactions read: ${transactions.length}`);
    return transactions;
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
            if (!['v0_p2wpkh', 'v1_p2tr'].includes(scriptpubkeyType)) return false; // Valid scriptpubkey types
            if (!scriptpubkeyAddress.startsWith('bc1')) return false; // Valid Bitcoin address format
            if (value <= 0) return false; // Positive value for input
        }
        // Validate each output (vout)
        for (const output of vout) {
            const scriptpubkeyType = output.scriptpubkey_type || '';
            const scriptpubkeyAddress = output.scriptpubkey_address || '';
            const value = output.value || 0;
            // Perform basic checks on output
            if (!['v0_p2wpkh', 'v1_p2tr'].includes(scriptpubkeyType)) return false; // Valid scriptpubkey types
            if (!scriptpubkeyAddress.startsWith('bc1')) return false; // Valid Bitcoin address format
            if (value <= 0) return false; // Positive value for output
        }
        return true; // Transaction is valid if all checks pass
    } catch (error) {
        console.log(`Error validating transaction: ${error}`);
        return false;
    }
}

// Function to calculate the block hash
function calculateBlockHash(blockHeader) {
    const blockHeaderBin = Buffer.from(blockHeader, 'hex');
    const blockHash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(blockHeaderBin).digest()).digest();
    return blockHash.reverse().toString('hex');
}

// Function to mine a block
function mineBlock(transactions, prevBlockHash, difficultyTarget) {
    let nonce = 0; // Initialize nonce to 0
    while (true) {
        const blockHeader = prevBlockHash + nonce.toString(16).padStart(8, '0'); // Append nonce to block header
        const blockHash = calculateBlockHash(blockHeader); // Calculate block hash
        if (BigInt('0x' + blockHash) < BigInt('0x' + difficultyTarget)) { // Check if block hash meets difficulty target
            const validTransactions = transactions.filter(validateTransaction); // Find valid transactions
            if (validTransactions.length === 0) throw new Error('No valid transactions to mine.'); // Ensure at least one valid transaction
            const coinbaseTransaction = validTransactions[0]; // Select the coinbase transaction
            const txidList = validTransactions.map(tx => tx.vin[0].txid); // Extract transaction IDs (txids)
            return { blockHeader, blockHash, coinbaseTransaction, txidList }; // Return mined block details
        }
        nonce++; // Increment nonce if hash does not meet target
    }
}

// Main function
function main() {
    const mempoolDir = './mempool'; // Path to the mempool folder
    const difficultyTarget = '0000ffff00000000000000000000000000000000000000000000000000000000'; // Difficulty target
    const prevBlockHash = '0000000000000000000000000000000000000000000000000000000000000000'; // Placeholder previous block hash
    
    try {
        const transactions = readTransactionsFromMempool(mempoolDir); // Read transactions from mempool
        const { blockHeader, blockHash, coinbaseTransaction, txidList } = mineBlock(transactions, prevBlockHash, difficultyTarget); // Mine a block
        const outputFileContent = `${blockHeader}\n${JSON.stringify(coinbaseTransaction)}\n${txidList.join('\n')}\n`; // Format output content
        fs.writeFileSync('output.txt', outputFileContent, 'utf8'); // Write output to file
    } catch (error) {
        console.log(`An error occurred: ${error}`);
        process.exit(1); // Exit with error status
    }
}

// Execute the main function
main();
