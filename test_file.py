import hashlib
import json
from tpMtree import *
from ecc_keypair import *
import pickle
from web3 import Web3
from web3.auto import w3
from eth_account.messages import encode_defunct
from hexbytes import HexBytes
from eth_account.messages import encode_defunct, _hash_eip191_message


from eth_keys import keys
from collections.abc import (
    Mapping,
)
import json
from typing import (
    NamedTuple,
    Union,
)

from eth_typing import (
    Address,
    Hash32,
)
from eth_utils.curried import (
    ValidationError,
    keccak,
    text_if_str,
    to_bytes,
    to_canonical_address,
    to_text,
)
from hexbytes import (
    HexBytes,
)

from eth_account._utils.structured_data.hashing import (
    hash_domain,
    hash_message as hash_eip712_message,
    load_and_validate_structured_message,
)
from eth_account._utils.validation import (
    is_valid_address,
)
from fbhtree import *
import sha3
from ethsign_key import Account

text_to_bytes = text_if_str(to_bytes)


# watch for updates to signature format
class SignableMessage(NamedTuple):
    """

    """
    version: HexBytes  # must be length 1
    header: HexBytes  # aka "version specific data"
    body: HexBytes  # aka "data to sign"
def to_32byte_hex(val):
   return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))


def _hash_eip191_message(signable_message: SignableMessage) -> Hash32:
    version = signable_message.version
    if len(version) != 1:
        raise ValidationError(
            "The supplied message version is {version!r}. "
            "The EIP-191 signable message standard only supports one-byte versions."
        )

    return keccak(

        b'1945' +
        signable_message.header +
        signable_message.body
    )


# watch for updates to signature format
def encode_intended_validator(
        validator_address: Union[Address, str],
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> SignableMessage:
    """

    """
    if not is_valid_address(validator_address):
        raise ValidationError(
            f"Cannot encode message with 'Validator Address': {validator_address}. "
            "It must be a checksum address, or an address converted to bytes."
        )
    message_bytes = to_bytes(primitive, hexstr=hexstr, text=text)
    return SignableMessage(
        b'\x00',  # version 0, as defined in EIP-191
        to_canonical_address(validator_address),
        message_bytes,
    )


def encode_structured_data(
        primitive: Union[bytes, int, Mapping] = None,
        *,
        hexstr: str = None,
        text: str = None) -> SignableMessage:
    """

    """
    if isinstance(primitive, Mapping):
        message_string = json.dumps(primitive)
    else:
        message_string = to_text(primitive, hexstr=hexstr, text=text)
    structured_data = load_and_validate_structured_message(message_string)
    return SignableMessage(
        b'\x01',
        hash_domain(structured_data),
        hash_eip712_message(structured_data),
    )


def encode_defunct(
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> SignableMessage:
    r"""

    """
    message_bytes = to_bytes(primitive, hexstr=hexstr, text=text)
    msg_length = (len(message_bytes))
    _len = bytes(to_32byte_hex(msg_length)[2:],encoding='utf-8')
    # Encoding version E defined by EIP-191
    return SignableMessage(
        b'E',
        b'7468657265756d205369676e6564204d6573736167653a0a' + _len,
        message_bytes,
    )


def defunct_hash_message(
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> HexBytes:
    """

    """
    signable = encode_defunct(primitive, hexstr=hexstr, text=text)
    hashed = _hash_eip191_message(signable)
    return HexBytes(hashed)



def to_32byte_hex(val):
   return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))


def adjust(array):
    if len(array) > 4:
        array[0] = bytes(array[0][2:],encoding='utf-8')
        array[1] = bytes(array[1][2:],encoding='utf-8')
        array[2] = binascii.hexlify(array[2].to_bytes(32,'big'))
        array[3] = binascii.hexlify(bytes(str(array[3]),encoding='utf-8'))
        array[4] = bytes(array[4][2:],encoding='utf')
        array[5] = binascii.b2a_hex(array[5].to_bytes(32,'big'))
        array[6] = bytes(array[6][2:],encoding='utf-8')
    else:
        array[0] = bytes(array[0][2:],encoding='utf-8')
        array[1] = bytes(array[1][2:],encoding='utf-8')
        array[2] = binascii.hexlify(array[2].to_bytes(32,'big'))
        array[3] = binascii.hexlify(bytes(str(array[3]),encoding='utf-8'))

    return array
def w3signature(json_file,private_key):
    value_dict = json_file.values()
    result = []

    for values in value_dict:
        result.append(values)
    result = adjust(result)
    msg = b''.join(result)
    message = encode_defunct(primitive=msg)
    signed_message = Account.sign_message(message, private_key)
    return to_32byte_hex(signed_message.signature)
    #return message
def PublickeytoAddress(public_key):
    keccak_hash = sha3.keccak_256(public_key.encode('utf-8')).hexdigest()
    return '0x'+keccak_hash[24:]






PK_SPO = "ff718dbb708550cb9663931d6181a6a7eaec7b9ae7e371241fc34908c3ab130b"
SK_SPO = "37ec8f07354846302e0c98ccee8a5b90690cffd4ccf14776b0dffb492a0a3d20"
RunnerPK_record = list()
PhotographerPK_record = list()
PreviousHash_dict = dict()
Reward_dict = dict()
pubkey = open('C:/Users/handsomelee/Desktop/pksklist/publickey.txt','rb')
publickey = pickle.load(pubkey)
prvkey = open('C:/Users/handsomelee/Desktop/pksklist/privatekey.txt','rb')
privatekey = pickle.load(prvkey)





for i in range(1,11):

    PK_R = (publickey)[1]
    PK_P = (publickey)[0]
    P_adr = PublickeytoAddress(PK_P)
    RunnerPK_record.append(PK_R)
    PhotographerPK_record.append(PK_P)
    #sigR = signature(str(json_request_withoutsigR),privatekey[publickey.index(PK_R)])
    #sigSPO = signature(str(json_receipt_withoutsig),str(SK_SPO))

    p = random.randint(1,10)

    json_request_withoutsigR = {'PK_Runner':PK_R, 'Photographer_address':P_adr, 'number of photo':p,'indexValue':str(PK_R)}

    sigR = w3signature((json_request_withoutsigR),privatekey[publickey.index(PK_P)])

    #index = calLeafIndex(a,4)
    json_request_withsigR = {'PK_Runner':PK_R, 'Photographer_address':P_adr, 'number of photo':p,'indexValue':str(PK_R),'sigClient':sigR}

    if PhotographerPK_record.count(PK_P) >= 2:


        json_receipt_withoutsig =  {'PK_Runner':PK_R, 'Photographer_address':P_adr, 'number of photo':p,'indexValue':str(PK_R), 
        'sigClient':sigR, 'reward':(Reward_dict[PK_P]) + p,'PreviousHash':PreviousHash_dict[PK_P]}
    else:
        json_receipt_withoutsig =  {'PK_Runner':PK_R, 'Photographer_address':P_adr, 'number of photo':p,'indexValue':str(PK_R), 
        'sigClient':sigR, 'reward':p,'PreviousHash':''}

    sigSPO = w3signature((json_receipt_withoutsig),SK_SPO)


    json_receipt_withsig = json_receipt_withoutsig
    json_receipt_withsig['sigSPO'] = sigSPO

    #print(PreviousHash_dict)
    #print("\n")
    #print(json_receipt_withsig)

    PreviousHash_dict[PK_P] = '0x'+hashstring(str(json_receipt_withsig))
    Reward_dict[PK_P] = (json_receipt_withsig['reward'])

    jname ="C:/Users//Desktop/test10/%d.json"%(i)
    with open(jname,'w') as f:
        json.dump(json_receipt_withsig,f)


    {'name':'ADATA','storage_location':'gcs','extension_id':'1','folder_id':'270','uploader_id':'1','indexValue':'8b7f324f-96af-42d2-9b9a-f3a411ca06f2.jpg','tab_id':'1'}