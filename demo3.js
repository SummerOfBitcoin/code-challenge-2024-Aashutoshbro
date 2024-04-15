const fs = require('fs');
const {
    serializeVarInt,
    reversedBytes,
    doubleSHA256,
    reverseHex,
    singleSHA256
} = require('./utils/utilFunctions');

function main() {
    const parsedArray = fetchDataFromFiles();
    operation(parsedArray);

    weightArray = JSON.parse(fs.readFileSync('./mempoolTempFinalArray/weightArray.json', 'utf8'));
    let countWeight = 0;
    weightArray.map((weight) => {
        if (weight >= 4000) {
            countWeight++;
        }

    })

    const { timestamp, bits, prevBlock_Hash, result, txid1, txids, serializedOut } = preMineBlock();

    let nonce = 0;
    let blockHeaderHash = mineBlock(timestamp, bits, prevBlock_Hash, result, nonce);
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";

    while (true) {
        if (blockHeaderHash < target) {
            break;
        } else {
            nonce++;
            blockHeaderHash = mineBlock(timestamp, bits, prevBlock_Hash, result, nonce);
        }
    }

    let blockHeaderSerializedHex = mined(timestamp, bits, prevBlock_Hash, result, nonce);

    // Adjust block header length to 80 bytes
    if (blockHeaderSerializedHex.length < 160) { // Check if length is less than 80 bytes (160 characters in hexadecimal representation)
        blockHeaderSerializedHex += "0".repeat(160 - blockHeaderSerializedHex.length); // Add padding to the end to make it 80 bytes
    } else if (blockHeaderSerializedHex.length > 160) { // If length is more than 80 bytes, trim it
        blockHeaderSerializedHex = blockHeaderSerializedHex.slice(0, 160);
    }

    console.log(blockHeaderSerializedHex);
    console.log(serializedOut);
    txids.forEach(txid => {
        console.log(txid);
    });
}

main();