function mineBlock(timestamp, bits, prevBlock_Hash, result, nonce, targetDifficulty) {
    const blockHeader = {
        "version": 0x00000007,
        "prevBlock_Hash": prevBlock_Hash,
        "merkleRoot": result,
        "timestamp": timestamp,
        "bits": bits,
        "nonce": nonce
    }

    while (true) {
        const blockHeaderSerializedHex = mined(blockHeader);
        const blockHeaderHash = doubleSHA256(Buffer.from(blockHeaderSerializedHex, 'hex'));
        
        // Check if the block hash meets the target difficulty
        if (blockHeaderHash < targetDifficulty) {
            return blockHeaderHash; // Return the valid block hash
        } else {
            nonce++; // Increment nonce for the next iteration
            blockHeader.nonce = nonce; // Update nonce in the block header
        }
    }
}

// Function to serialize the block header
function mined(blockHeader) {
    const blockHeaderSerialized = [];
    const versionBytes = Buffer.alloc(4);
    versionBytes.writeUInt32LE(blockHeader.version);
    blockHeaderSerialized.push(...versionBytes);

    const prevBlock_HashBytes = Buffer.alloc(32);
    prevBlock_HashBytes.writeUInt32LE(blockHeader.prevBlock_Hash);
    blockHeaderSerialized.push(...prevBlock_HashBytes);

    const timestampBytes = Buffer.alloc(4);
    timestampBytes.writeUInt32LE(blockHeader.timestamp);
    blockHeaderSerialized.push(...timestampBytes);

    const bitsBytes = Buffer.alloc(4);
    bitsBytes.writeUInt32LE(blockHeader.bits);
    blockHeaderSerialized.push(...bitsBytes);

    const nonceBytes = Buffer.alloc(4);
    nonceBytes.writeUInt32LE(blockHeader.nonce);
    blockHeaderSerialized.push(...nonceBytes);

    const blockHeaderSerializedHex = blockHeaderSerialized.map(byte => {
        return byte.toString(16).padStart(2, '0');
    }).join('');

    return blockHeaderSerializedHex;
}

// Example usage:
const timestamp = 0x609be1c9; // Example timestamp
const bits = 0x1d00ffff; // Example bits
const prevBlock_Hash = 0x00000000000000000000000000000000; // Example previous block hash
const result = "123456789abcdef"; // Example merkle root
let nonce = 0;
const targetDifficulty = "0000ffff00000000000000000000000000000000000000000000000000000000"; // Example target difficulty

const validBlockHash = mineBlock(timestamp, bits, prevBlock_Hash, result, nonce, targetDifficulty);
console.log("Valid Block Hash:", validBlockHash);
