
from tpMtree import *
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


f = open('C:/Users/handsomelee/Desktop/test/999.json','r')
r = json.load(f)
SK_SPO = "37ec8f07354846302e0c98ccee8a5b90690cffd4ccf14776b0dffb492a0a3d20"
sigSPO = r['sigSPO']
del r['sigSPO']
f.close()
def to_32byte_hex(val):
   return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))
def adjust(array):
    array[0] = bytes(array[0][2:],encoding='utf-8')
    array[1] = bytes(array[1][2:],encoding='utf-8')
    array[2] = binascii.hexlify(bytes(str(array[2]),encoding='utf-8'))
    array[3] = binascii.hexlify(bytes(str(array[3]),encoding='utf-8'))
    array[4] = bytes(array[4][2:],encoding='utf')
    array[5] = binascii.hexlify(bytes(str(array[5]),encoding='utf-8'))
    array[6] = bytes(array[6][2:],encoding='utf-8')
    return array   
class AuditingMessage():
    def __init__(self,_slice,kvpairs):
        self._slice = _slice
        self.kvpairs = kvpairs
 
    def AMsignature(self,private_key):  
        result = []  
        S = self._slice
        K = self.kvpairs       
        for i in S:
            i = bytes(i[2:],encoding='utf-8')
            result.append(i)
        for y in K:
            y = bytes(y[2:],encoding='utf-8')
            result.append(y)
        msg = b''.join(result)
        message = encode_defunct(primitive=msg)
        signed_message = Account.sign_message(message, private_key)
        return signed_message.messageHash,to_32byte_hex(signed_message.r),to_32byte_hex(signed_message.s),signed_message.v,signed_message.signature,msg,message    
    
a = AuditingMessage(["0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "0xfdf20d94e3dfb0a2609e11aa2699e5298bf771cba184062d47facca600d91da3", "0x2f42896c03664b6027eec1c639421e038daab52a71a128720d939584f9ea1eec", "0x9132daf1bfb5894ed7d6149c88d1e757d8ca6a74ae6419a6beaee148b3f8b497", "0x5383a0f12647f3cd0884c7d50d1c71f6bed8c0913701a75419b96d2d1d223f68", "0xb348df7357e4bf32f2a6c5960dadb14fdf0b384ea3a53e71a05f03c26d572c15", "0x64d94fead8107247211cacf4c135398cbfae1844c8826587c50650cf7b7f13a0", "0x84ab31f524bd83f876816a9cc54a77d4668d516bc752605cb10a0109ea7f43a7", "0xbe59905a6fa0d2bd040b877b1227504ce8574587e8a062c60d4f445feb3bcc3b", "0xc145333980d620683d3e96ac512078152b8f44be204f4a82f61ec4bcbb84d75b", "0xea5c5780eef59329cc2a74093a9ec9d78b3331e84bbf10f5d806877d232996d5", "0x6a857ff49801331751e48236a17c88c4833116e17bcff6c5a76d859cabda3331", "0xa452c0b83a99db72be3a6940d4a7c928169899e9b05868f615aa3fb415352d3a", "0x11b72602137bb00ffdff6e756222127076630a3f9a23f354ae43595b26ec684c", "0xf9b6b0f01ec87ba1e675c87481fcdc11b43548448e7c27dcb85fa93cd6aa5c16", "0x8ad664be2432ac7addaa491aabc6a6e0d28928f99678cde3be885694493deee8", "0xcafecc72be753589f93671f0d6c9dba44faf103aa3999ef73fbc3ea392f96d0a", "0x722087495c0d9e1847155751e499f64238b3afab24f28a42e52d3c88c774e1c5", "0xb8f0e58d488e3c0b222d7a07b238786d9fcd5be49b7a255f5089dc109e2215ce", "0x7ea2d988a1c6a82c8e6bd07ce68ab138147fe1d821d1ca1d8109ccae369c95bd", "0xc093d8819baaea8144d8ff904c17354071b5a633699a9f81c56334b66b9b64bc", "0x0b6173f4bf0bb37587cae7ab2d2579e622c09eac8a3dda196a1101e34b733449", "0x125dd1198d9fda7fe77686a4101cde4bab6860d1478eed6a27a6a8c90278dc16", "0xb61598e01ec55e68caf2daa9d3c0bc8cee0dc2720a6b08c060d90b2f76719086", "0xe11746324aa6ce20024a6e4796ae38d2dce7d5e015071a4a2cc96c9b71fafb32", "0xd093954c282432b667804715bf35505c516a761bbd410aa86e4872a0892532ff", "0x6d65e95a4349c3811da26a9c8d6ca23cfc3b9ef93752a87cc65004bddbed2547", "0xe3b4036e156dd6ccf9e41e36b011fd00f79645e361d02a9484eaba96e3be7179", "0x9ab9ba963eadee5aab8643d4f2e8c78d23a9a39e088248538c5ca31fcc6dcdb0"]
,["0x71fc5d73bd4ef773359ebbb31cfb51350ce135b9fc8b3bba8d12ceb009510976", "0xc5ccaa1e332db476f88e97c2be4c986a552a6e54f8177073ae5e3b46ae9c5cfa", "0xe3f97457149aff0f6516f6c17fc9cbd56f6dbbef5ac41bdb52f4ea6ac82a617b", "0x54711b5a2c5c23235f7886a547cba6faddb3fbc14390db3211d6fddb5aa8fa60", "0x1c7fbe1fa73eeb8c79d5da886853926bb453ad410d42bfad88c59075c3894601", "0x0b2bf24419955a5bc9c785814eb2e128f28e14e43a43e60af1c5446b224c8e05", "0xe3fae8f20b11780b1352457b8602f655133f9bcbcf4594c2659a79702e8c0cf4", "0xcd273b1385b946ff2bb84728175486d157138b5a5af1ad073438cc16de4ead88", "0x038fee9a4d22cd49e31278ab31f81e3503372edd8b6a3463db34b7b8c4d94e44", "0xda0fdde04ab61372b9bad45f7313be2cdb3221d8a623f4e58009a4f7e659e848", "0x71ff95f1a68fe01da0f110335252e288aaae4bcb5db780ed1b962e761cad1de7", "0x30352a0aefde8b38b5c4e4e89b25c479941df84d898031fdef3534f5b2243d1c", "0x71ff8a27950f469bc18d044df6f569f5728fd045d3c77e707779adb6c7f5f523", "0x7230bc5cfa5e4e35ddffd2d5277b5fcc281c516710a66e606ceb6b3f3d2e522f", "0x71fff6257434188bdc266a96dfd290d08dd526782407e41f666ee1eb2c784c62", "0x27db9ed51c1d6ee3ab89569b2b6d7a7e8ff1e22c989a29cb4d64fbacdab33dfd", "0xe3ff2c0bbaf1771f5ecbeb69b2b7b43c9f1a9329645906452b1c28ce05df85d0", "0x83992e84652bd5306abe4d0165fdfb8928983d27956fdf715a0a3c69287b0f8b", "0xe3f8dfae41dd6b9272bc3cb800e7ee6e1f7ae3dd99bd1d3a8352e7fbd139f73e", "0x0407231c22c3cf2e2654803f6fa602bac09d3d7db1cf6b3228eb24b2e6fecd9d"]
)

imformation = AuditingMessage.AMsignature(a,SK_SPO)
print("message hash : {0}".format(to_32byte_hex(imformation[0])))
print("r : {0}".format((imformation[1])))
print("s : {0}".format((imformation[2])))
print("v : {0}".format(imformation[3]))
print("signature : {0}".format(to_32byte_hex(imformation[4])))
#print("message_noencode : {0}".format(imformation[5]))
#print("message_encode : {0}".format(imformation[6]))


"""def w3signature(json_file,private_key):
    value_dict = json_file.values()
    result = []

    for value in value_dict:
        result.append(str(value))
    result = adjust(result)
    msg = b''.join((result))
    message = encode_defunct(primitive=msg)
    signed_message = Account.sign_message(message, private_key)
    return signed_message.messageHash,to_32byte_hex(signed_message.r),to_32byte_hex(signed_message.s),signed_message.v,signed_message.signature,msg,message
def AuditingMessageSIG(AuditingMessage):


"""
"""
print(r)    

imformation = AMsignature(r,SK_SPO)
print("message hash : {0}".format(to_32byte_hex(imformation[0])))
print("r : {0}".format((imformation[1])))
print("s : {0}".format((imformation[2])))
print("v : {0}".format(imformation[3]))
print("signature : {0}".format(to_32byte_hex(imformation[4])))
print("message_noencode : {0}".format(imformation[5]))
print("message_encode : {0}".format(imformation[6]))
print(sigSPO)
count = 0
"""