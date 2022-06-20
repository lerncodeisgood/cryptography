import hashlib
import sha3
import binascii
#對byte進行sha256 hash
def hashbyte(b):
    h = hashlib.sha256()
    h.update(b)
    hash_byte = h.hexdigest()
    return hash_byte

#對string進行sha256 hash
def hashstring(string):
    h = hashlib.sha256()
    h.update(string.encode('utf-8'))
    hash_string = h.hexdigest()
    return hash_string
#對key-value pairs list concanate 進行hash		
def leafnodehash(keyvaluedict) :

    keylist = keyvaluedict.keys()
    concanatelist=list()
    for key in keylist:
        concanate =  (key) + (keyvaluedict[key])
        concanatelist.append(concanate)
        concanatebytes = b''.join(concanatelist)	
    leafnodehash = hashbyte(concanatebytes)
    return leafnodehash
#concanate左子節點與右子節點再hash	
def hash_LnR(leaf_left, leaf_right):
    

    leaf_left = binascii.a2b_hex(leaf_left) #為了符合Solidity，轉成byte型態
    

    leaf_right = binascii.a2b_hex(leaf_right)
    parenthash = leaf_left+leaf_right
    root_hash = hashbyte(parenthash)
    return root_hash
#keccak256的hash function
def sha3_keccak256(bytes):
    h = sha3.keccak_256()
    h.update(bytes)
    result = h.hexdigest()
    return result