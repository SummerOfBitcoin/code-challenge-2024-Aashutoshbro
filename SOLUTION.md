# Verifying a Signature
# We can now verify a signature using some of the primitives that we have:
```
>>> from ecc import S256Point, G, N
>>> z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
>>> r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
>>> s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
>>> px = 0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574
>>> py = 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4
>>> point = S256Point(px, py)
>>> s_inv = pow(s, N-2, N) 
>>> u = z * s_inv % N
>>> v = r * s_inv % N
>>> p

We do this using some of the primitives that we have:
>>> from ecc import S256Point, G, N
>>> from helper import hash256
>>> e = int.from_bytes(hash256(b'my secret'), 'big')
>>> z = int.from_bytes(hash256(b'my message'), 'big')
>>> k = 1234567890
>>> r = (k*G).x.num
>>> k_inv = pow(k, N-2, N)
>>> s = (z+r*e) * k_inv % N
>>> point = e*G
>>> print(point)
S256Point(028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52, \
0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2)
>>> print(hex(z))
0x231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78
>>> print(hex(r))
0x2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22
>>> print(hex(s))
0xbb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9

```





# Again, the procedure is pretty straightforward. We can update the sec method to
# handle compressed SEC keys:
```
class S256Point(Point):
...
 def sec(self, compressed=True):
 '''returns the binary version of the SEC format'''
 if compressed:
 if self.y.num % 2 == 0:
 return b'\x02' + self.x.num.to_bytes(32, 'big')
 else:
 return b'\x03' + self.x.num.to_bytes(32, 'big')
 else:
 return b'\x04' + self.x.num.to_bytes(
  
```


# der signature format
```
  class Signature:
...
 def der(self):
 rbin = self.r.to_bytes(32, byteorder='big')
 # remove all null bytes at the beginning
 rbin = rbin.lstrip(b'\x00')
 # if rbin has a high bit, add a \x00
 if rbin[0] & 0x80:
 rbin = b'\x00' + rbin
 result = bytes([2, len(rbin)]) + rbin
 sbin = self.s.to_bytes(32, byteorder='big')
 # remove all null bytes at the beginning
 sbin = sbin.lstrip(b'\x00')
 # if sbin has a high bit, add a \x00
 if sbin[0] & 0x80:
 sbin = b'\x00' + sbin
 result += bytes([2, len(sbin)]) + sbin
 return bytes([0x30, len(result)]) + result

```
# Base58 Encoding
```
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
...
def encode_base58(s):
 count = 0
 for c in s:
 if c == 0:
 count += 1
 else:
 break
 num = int.from_bytes(s, 'big')
 prefix = '1' * count
 result = ''
 while num > 0:
 num, mod = divmod(num, 58)
 result = BASE58_ALPHABET[mod] + result
 return prefix + result 
```

# Transaction Components
# At a high level, a transaction really only has four components. They are:
# 1. Version
# 2. Inputs
# 3. Outputs
# 4. Locktime
```

 class Tx:
 def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
 self.version = version
 self.tx_ins = tx_ins
 self.tx_outs = tx_outs
 self.locktime = locktime
 self.testnet = testnet
 def __repr__(self):
 tx_ins = ''
 for tx_in in self.tx_ins:
 tx_ins += tx_in.__repr__() + '\n'
 tx_outs = ''
 for tx_out in self.tx_outs:
 tx_outs += tx_out.__repr__() + '\n'
 return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
 self.id(),
 self.version,
 tx_ins,
 tx_outs,
 self.locktime,
 )
 def id(self):
 '''Human-readable hexadecimal of the transaction hash'''
 return self.hash().hex()
 def hash(self):
 '''Binary hash of the legacy serialization'''
 return hash256(self.serialize())[::-1]


```

#  Now that we know what the fields are, we can start creating a TxIn class in Python:
```
class TxIn:
 def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
 self.prev_tx = prev_tx
 self.prev_index = prev_index
 if script_sig is None:
 self.script_sig = Script()
 else:
 self.script_sig = script_sig
 self.sequence = sequence
 def __repr__(self):
 return '{}:{}'.format(
 self.prev_tx.hex(),
 self.prev_index,
 )
```

# We can now start coding the TxOut class:
```
class TxOut:
 def __init__(self, amount, script_pubkey):
 self.amount = amount
 self.script_pubkey = script_pubkey
 def __repr__(self):
 return '{}:{}'.format(self.amount, self.script_pubkey)
```

# Lastly, we can serialize Tx:
```
 class Tx:
...
 def serialize(self):
 '''Returns the byte serialization of the transaction'''
 result = int_to_little_endian(self.version, 4)
 result += encode_varint(len(self.tx_ins))
 for tx_in in self.tx_ins:
 result += tx_in.serialize()
 result += encode_varint(len(self.tx_outs))
 for tx_out in self.tx_outs:
 result += tx_out.serialize()
 result += int_to_little_endian(self.locktime, 4)
 return result
```

# Coding a Script Parser and Serializer
# Now that we know how Script works, we can write a script parser:
```
class Script:
 def __init__(self, cmds=None):
 if cmds is None:
 self.cmds = []
 else:
 self.cmds = cmds
 ...
 @classmethod
 def parse(cls, s):
 length = read_varint(s)
 cmds = []
 count = 0
 while count < length:
 current = s.read(1)
 count += 1
 current_byte = current[0]
 if current_byte >= 1 and current_byte <= 75:
 n = current_byte
 cmds.append(s.read(n))
 count += n
 elif current_byte == 76:
 data_length = little_endian_to_int(s.read(1))
 cmds.append(s.read(data_length))
 count += data_length + 1
 elif current_byte == 77:
 data_length = little_endian_to_int(s.read(2))
 cmds.append(s.read(data_length))
 count += data_length + 2
 else:
 op_code = current_byte
 cmds.append(op_code)
 if count != length:
 raise SyntaxError('parsing script failed')
 return cls(cmds)
```
# Each command is either an opcode to be executed or an element to be pushed
# onto the stack.
# Script serialization always starts with the length of the entire script.
# We parse until the right amount of bytes are consumed.
# The byte determines if we have an opcode or element.
# This converts the byte into an integer in Python.
# For a number between 1 and 75 inclusive, we know the next n bytes are an
# element.
# 76 is OP_PUSHDATA1, so the next byte tells us how many bytes to read.
# 77 is OP_PUSHDATA2, so the next two bytes tell us how many bytes to read.
# We have an opcode that we store.
# The script should have consumed exactly the length of bytes we expected; other‐
# wise, we raise an error.


# We can similarly write a script serializer:
```
class Script:
...
 def raw_serialize(self):
 result = b''
 for cmd in self.cmds:
 if type(cmd) == int:
 result += int_to_little_endian(cmd, 1)
 else:
 length = len(cmd)
 if length < 75:
 result += int_to_little_endian(length, 1)
 elif length > 75 and length < 0x100:
 result += int_to_little_endian(76, 1)
 result += int_to_little_endian(length, 1)
 elif length >= 0x100 and length <= 520:
 result += int_to_little_endian(77, 1)
 result += int_to_little_endian(length, 2)
 else:
 raise ValueError('too long an cmd')
 result += cmd
 return result
 def serialize(self):
 result = self.raw_serialize()
 total = len(result)
 return encode_varint(total) + result
```

# If the command is an integer, we know that’s an opcode.
# If the length is between 1 and 75 inclusive, we encode the length as a single byte.
# For any element with length from 76 to 255, we put OP_PUSHDATA1 first, then
# encode the length as a single byte, followed by the element.
# For an element with a length from 256 to 520, we put OP_PUSHDATA2 first, then
# encode the length as two bytes in little endian, followed by the element.
# Any element longer than 520 bytes cannot be serialized.
# Script serialization starts with the length of the entire script.
# izing the ScriptSig and ScriptPubKey fields.


# verify signature
```
>>> from ecc import S256Point, Signature
>>> sec = bytes.fromhex('0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e\
213bf016b278a')
>>> der = bytes.fromhex('3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031c\
cfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9\
c8e10615bed')
>>> z = 0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6
>>> point = S256Point.parse(sec)
>>> signature = Signature.parse(der)
>>> print(point.verify(z, signature))
True
```
<!-- 
Making the Transaction
We have a plan for a new transaction with one input and two outputs. But first, let’s
look at some other tools we’ll need.
We need a way to take an address and get the 20-byte hash out of it. This is the oppo‐
site of encoding an address, so we call the function decode_base58: -->
```
def decode_base58(s):
 num = 0
 for c in s:
 num *= 58
 num += BASE58_ALPHABET.index(c)
 combined = num.to_bytes(25, byteorder='big')
 checksum = combined[-4:]
 if hash256(combined[:-4])[:4] != checksum:
 raise ValueError('bad address: {} {}'.format(checksum,
 hash256(combined[:-4])[:4]))
 return combined[1:-4] 
```


<!-- Coding p2sh
The special pattern of RedeemScript, OP_HASH160, hash160, and OP_EQUAL needs han‐
dling. The evaluate method in script.py is where we handle the special case:
class Script: -->
```
...
 def evaluate(self, z):
...
 while len(commands) > 0:
 command = commands.pop(0)
 if type(command) == int:
...
 else:
 stack.append(cmd)
 if len(cmds) == 3 and cmds[0] == 0xa9 \
 and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
 and cmds[2] == 0x87:
 cmds.pop()
 h160 = cmds.pop()
 cmds.pop()
 if not op_hash160(stack):
 return False
 stack.append(h160)
 if not op_equal(stack):
 return False
 if not op_verify(stack):
 LOGGER.info('bad p2sh h160')
 return False
 redeem_script = encode_varint(len(cmd)) + cmd
 stream = BytesIO(redeem_script)
 cmds.extend(Script.parse(stream).cmds)
 ```


<!-- for the block header -->
```
class Block:
 def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce):
 self.version = version
 self.prev_block = prev_block
 self.merkle_root = merkle_root
 self.timestamp = timestamp
 self.bits = bits
 self.nonce = nonce
```




<!-- for the version -->

```
Checking for these features is relatively straightforward:
>>> from io import BytesIO
>>> from block import Block
>>> b = Block.parse(BytesIO(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b\
4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3\
f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')))
>>> print('BIP9: {}'.format(b.version >> 29 == 0b001))
BIP9: True
>>> print('BIP91: {}'.format(b.version >> 4 & 1 == 1))
BIP91: False
168 | Chapter 9: Blocks
>>> print('BIP141: {}'.format(b.version >> 1 & 1 == 1))
BIP141: True
```

<!-- target making -->
```
target = coefficient × 256exponent–3
This is how we calculate the target given the bits field in Python:
>>> from helper import little_endian_to_int
>>> bits = bytes.fromhex('e93c0118')
>>> exponent = bits[-1]
>>> coefficient = little_endian_to_int(bits[:-1])
>>> target = coefficient * 256**(exponent - 3)
>>> print('{:x}'.format(target).zfill(64))
0000000000000000013ce9000000000000000000000000000000000000000000
```

