import crcmod.predefined
from typing import Tuple, Any, Dict
from io import BytesIO

# Import pyasn1 types and codecs
from pyasn1.type import univ, tag
from pyasn1.codec.ber import encoder as ber_encoder, decoder as ber_decoder
from pyasn1.error import PyAsn1Error

# --- CRC Functions ---
# Mode 1a/1b: 16-bit FCS (CCITT Q.921 CRC16) - Use 'crc-ccitt-false'
crc16_func = crcmod.predefined.mkCrcFun('crc-ccitt-false')
# Mode 2: 32-bit FCS (ISO 9314-2 / ANSI X3.66 / Ethernet / PKZIP)
crc32_func = crcmod.predefined.mkCrcFun('crc-32')

# --- DFA <-> VPI/VCI Mapping ---
def dfa1_to_vpivci(dfa: int) -> Tuple[int, int]:
    if not (0 <= dfa <= 1023): raise ValueError("Mode 1 DFA must be between 0 and 1023")
    vpi = ((dfa >> 6) & 0x0F)
    vci = (((dfa >> 4) & 0x03) << 4) | ((dfa >> 0) & 0x0F) # Corrected shift for vci_part1
    return vpi, vci

def vpivci_to_dfa1(vpi: int, vci: int) -> int:
    vpi_part = (vpi & 0x0F) << 6
    vci_part1 = ((vci >> 4) & 0x03) << 4 # Corrected shift
    vci_part0 = (vci & 0x0F) << 0
    dfa = vpi_part | vci_part1 | vci_part0
    return dfa

def dfa2_to_vpivci(dfa: int) -> Tuple[int, int]:
    if not (0 <= dfa <= 0xFFFFFF): raise ValueError("Mode 2 DFA must be between 0 and 0xFFFFFF")
    vpi_5_0 = (dfa >> 18) & 0x3F
    vpi_7_6 = (dfa >> 16) & 0x03
    vpi = (vpi_7_6 << 6) | vpi_5_0
    vci_15_14 = (dfa >> 14) & 0x03
    vci_13_7  = (dfa >> 7)  & 0x7F
    vci_6_0   = (dfa >> 0)  & 0x7F
    vci = (vci_15_14 << 14) | (vci_13_7 << 7) | vci_6_0
    return vpi, vci

def vpivci_to_dfa2(vpi: int, vci: int) -> int:
    vpi_part1 = (vpi & 0x3F) << 18
    vpi_part2 = ((vpi >> 6) & 0x03) << 16
    vci_part1 = ((vci >> 14) & 0x03) << 14
    vci_part2 = ((vci >> 7) & 0x7F) << 7
    vci_part3 = (vci & 0x7F) << 0
    dfa = vpi_part1 | vpi_part2 | vci_part1 | vci_part2 | vci_part3
    return dfa


# --- LMI Encoding Helper Functions ---

def encode_dxi_oid(oid_str: str) -> bytes:
    """Encodes an OID string ('1.3.6.1...') into DXI custom 7-bit format."""
    parts = [int(p) for p in oid_str.split('.') if p]
    if not parts or len(parts) < 2:
        raise ValueError("Invalid OID string format")

    if parts[0] > 2 or (parts[0] < 2 and parts[1] >= 40):
         raise ValueError("Invalid first two OID components")
    first_val = parts[0] * 40 + parts[1]
    encoded_parts = [first_val] + parts[2:]

    final_result = bytearray()
    encoded_subids = []

    for part in encoded_parts:
        if part == 0:
            encoded_subids.append(bytes([0x00]))
            continue

        sub_id_bytes = bytearray()
        val = part
        sub_id_bytes.insert(0, val & 0x7F)
        val >>= 7
        while val > 0:
             sub_id_bytes.insert(0, (val & 0x7F) | 0x80)
             val >>= 7

        if sub_id_bytes[0] == 0x80:
             raise ValueError(f"Subidentifier {part} results in invalid first byte 0x80 in DXI OID encoding")
        encoded_subids.append(bytes(sub_id_bytes))

    for sub_bytes in encoded_subids:
        final_result.extend(sub_bytes)

    return bytes(final_result)


def decode_dxi_oid(stream: BytesIO) -> str:
    """Decodes DXI custom 7-bit OID format from a byte stream."""
    sub_ids = []
    original_len = len(stream.getvalue()) # Total length of bytes provided for OID
    start_pos = stream.tell()

    while stream.tell() < original_len: # Loop over sub-identifiers
        sub_id_val = 0
        first_byte = True
        sub_id_start_pos = stream.tell()

        while True: # Loop over bytes within a sub-identifier
            byte = stream.read(1)
            if not byte:
                raise ValueError("Unexpected end of stream during DXI OID sub-identifier decode")

            b = byte[0]
            if first_byte and b == 0x80:
                 raise ValueError("Invalid DXI OID encoding: first byte of sub-identifier is 0x80")
            first_byte = False

            sub_id_val = (sub_id_val << 7) | (b & 0x7F)
            if not (b & 0x80): # Check continuation bit (MSB=0 means end of sub-id)
                break

            # Safety check: prevent infinite loop if stream doesn't end sub-id correctly
            if stream.tell() >= original_len and (b & 0x80):
                 raise ValueError("OID stream ended unexpectedly with continuation bit set")

        sub_ids.append(sub_id_val)

    if stream.tell() != original_len:
         print(f"Warning: decode_dxi_oid did not consume exactly expected bytes. Pos: {stream.tell()}, Expected: {original_len}")

    if not sub_ids:
        return ""
    first_val = sub_ids[0]
    oid_list = [first_val // 40, first_val % 40] + sub_ids[1:]
    return ".".join(map(str, oid_list))


def encode_ber_length(length: int) -> bytes:
    """Encodes a length according to BER definite short/long form."""
    if length < 0:
        raise ValueError("Length cannot be negative")
    if length < 128:
        return bytes([length])
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        num_len_octets = len(len_bytes)
        if num_len_octets > 126:
            raise ValueError("Length too large to encode in BER long form")
        return bytes([0x80 | num_len_octets]) + len_bytes

def decode_ber_length(stream: BytesIO) -> int:
    """Decodes a BER length from a byte stream."""
    initial_byte = stream.read(1)
    if not initial_byte:
        raise ValueError("Cannot decode length: unexpected end of stream")
    b0 = initial_byte[0]
    if not (b0 & 0x80):
        return b0
    else:
        num_len_octets = b0 & 0x7F
        if num_len_octets == 0:
            raise ValueError("BER indefinite length form is not supported")
        if num_len_octets > 4:
             raise ValueError(f"BER long form length field too large: {num_len_octets} octets")

        len_bytes = stream.read(num_len_octets)
        if len(len_bytes) < num_len_octets:
            raise ValueError("Unexpected end of stream reading BER long form length")
        return int.from_bytes(len_bytes, 'big')


# --- ASN.1 Value Encoding/Decoding Helpers ---

# Mapping Python types to pyasn1 types for encoding
PYTHON_TO_ASN1_MAP: Dict[type, Any] = {
    int: univ.Integer,
    str: lambda x: univ.OctetString(x.encode('utf-8')), # Assume UTF-8 for strings
    bytes: univ.OctetString,
    type(None): univ.Null,
    tuple: univ.ObjectIdentifier, # Expect OID as tuple e.g. (1,3,6,1...)
}
# Mapping pyasn1 tags to Python types for decoding
ASN1_TAG_TO_PYTHON_MAP: Dict[tag.TagSet, type] = {
    univ.Integer.tagSet: int,
    univ.OctetString.tagSet: bytes, # Decode OctetString always to bytes
    univ.Null.tagSet: type(None),
    univ.ObjectIdentifier.tagSet: tuple, # Decode OID to tuple
}

def encode_asn1_value(value: Any) -> bytes:
    """Encodes a Python value into its BER TLV representation."""
    asn1_type_constructor = PYTHON_TO_ASN1_MAP.get(type(value))
    if asn1_type_constructor:
        asn1_value = asn1_type_constructor(value)
        return ber_encoder.encode(asn1_value)
    elif isinstance(value, str) and value.count('.') > 0: # Allow encoding OID from string
         try:
             asn1_value = univ.ObjectIdentifier(value)
             return ber_encoder.encode(asn1_value)
         except PyAsn1Error:
              raise ValueError(f"Cannot encode value '{value}' as ASN.1 ObjectIdentifier or OctetString")
    else:
        raise TypeError(f"Unsupported Python type for ASN.1 encoding: {type(value)}")


def decode_asn1_value(value_bytes: bytes) -> Any:
    """Decodes BER TLV bytes into a Python value."""
    try:
        asn1_value, remaining_bytes = ber_decoder.decode(value_bytes, asn1Spec=univ.Any())
        if remaining_bytes:
            print(f"Warning: Trailing bytes after decoding ASN.1 value: {remaining_bytes!r}")

        py_type = ASN1_TAG_TO_PYTHON_MAP.get(asn1_value.tagSet)
        if py_type is int: return int(asn1_value)
        elif py_type is bytes: return bytes(asn1_value)
        elif py_type is type(None): return None
        elif py_type is tuple: return tuple(asn1_value) # OID as tuple
        else:
            print(f"Warning: No direct Python type mapping for ASN.1 tag: {asn1_value.tagSet}")
            return asn1_value # Return the pyasn1 object itself
    except PyAsn1Error as e:
        raise ValueError(f"Failed to decode ASN.1 BER value: {e}")
