import struct
from typing import List, NamedTuple, Any, Dict
from io import BytesIO

# Import pyasn1 types and codecs
from pyasn1.type import univ
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.error import PyAsn1Error

from dxi_constants import LMIType, LMIErrorStatus, LMITrapType
from dxi_utils import (
    encode_dxi_oid, decode_dxi_oid,
    encode_ber_length, decode_ber_length,
    encode_asn1_value, decode_asn1_value,
    ASN1_TAG_TO_PYTHON_MAP # Import map needed here too
)

# --- LMI PDU Structures ---
class LMIObject(NamedTuple):
    oid: str # OID string notation (e.g., "1.3.6.1.4.1.353.2.1.1")
    value: Any # Python native type (int, str, bytes, None, tuple for OID value)

class LMIPDU:
    """Base class for LMI PDUs with proper encoding."""
    def __init__(self, pdu_type: LMIType, objects: List[LMIObject]):
        self.pdu_type = pdu_type
        self.objects = objects if objects else []
        self.object_count = len(self.objects)
        if self.object_count > 255:
             raise ValueError("Cannot have more than 255 objects")

    def _pack_header(self) -> bytes:
        raise NotImplementedError("Subclasses must implement _pack_header")

    def _get_header_len(self) -> int:
         raise NotImplementedError("Subclasses must implement _get_header_len")

    def pack(self) -> bytes:
        """Packs the LMI PDU into bytes using DXI structure and BER for values."""
        header = self._pack_header()
        packed_objects = bytearray()

        for obj in self.objects:
            try:
                # 1. Encode OID to DXI format
                dxi_oid_bytes = encode_dxi_oid(obj.oid)
                # 2. Encode OID length using BER length rules
                oid_len_bytes = encode_ber_length(len(dxi_oid_bytes))
                # 3. Encode Value to BER TLV format
                value_tlv_bytes = encode_asn1_value(obj.value)

                # Concatenate: OID Length | DXI OID | Value TLV
                packed_objects.extend(oid_len_bytes)
                packed_objects.extend(dxi_oid_bytes)
                packed_objects.extend(value_tlv_bytes)
            except Exception as e:
                # Add context to the error during packing
                raise RuntimeError(f"Error packing LMI object (OID: {obj.oid}): {e}") from e

        return header + bytes(packed_objects)

    @classmethod
    def unpack(cls, pdu_bytes: bytes) -> 'LMIPDU':
        """Unpacks bytes into an LMI PDU object."""
        stream = BytesIO(pdu_bytes)
        if not pdu_bytes: raise ValueError("Empty LMI PDU")
        pdu_type_val = pdu_bytes[0]
        try:
            pdu_type = LMIType(pdu_type_val)
        except ValueError:
            raise ValueError(f"Unknown LMI PDU type: {pdu_type_val}")

        target_cls = PDU_TYPE_TO_CLASS.get(pdu_type) # Use global map defined below
        if not target_cls:
             raise NotImplementedError(f"No specific unpack logic registered for PDU type {pdu_type}")

        return target_cls._unpack_from_stream(stream)

    @classmethod
    def _unpack_from_stream(cls, stream: BytesIO) -> 'LMIPDU':
         raise NotImplementedError("Subclasses must implement _unpack_from_stream")

    @staticmethod
    def _static_unpack_objects(stream: BytesIO, obj_count: int) -> List[LMIObject]:
        """Helper to unpack the sequence of LMI objects."""
        objects = []
        for i in range(obj_count):
            oid_str = f"obj_{i+1}_oid_placeholder" # Placeholder
            value = f"obj_{i+1}_value_placeholder" # Placeholder
            try:
                # 1. Decode OID Length
                oid_len = decode_ber_length(stream)
                # 2. Read DXI OID bytes
                dxi_oid_bytes = stream.read(oid_len)
                if len(dxi_oid_bytes) < oid_len: raise ValueError(f"Unexpected EOS reading DXI OID obj {i+1}")
                # 3. Decode DXI OID bytes
                oid_stream = BytesIO(dxi_oid_bytes)
                oid_str = decode_dxi_oid(oid_stream)
                if oid_stream.read(): print(f"Warning: Trailing bytes decoding DXI OID obj {i+1}")

                # 4. Decode Value BER TLV
                current_pos = stream.tell()
                remaining_substrate_bytes = stream.read()
                stream.seek(current_pos)
                if not remaining_substrate_bytes:
                     raise ValueError(f"Unexpected end of stream before reading Value TLV for object {i+1}")

                decoded_value, remaining_bytes_after_decode = ber_decoder.decode(
                    remaining_substrate_bytes, asn1Spec=univ.Any()
                )
                bytes_consumed = len(remaining_substrate_bytes) - len(remaining_bytes_after_decode)
                stream.seek(current_pos + bytes_consumed)

                # Convert pyasn1 value to Python type
                py_type = ASN1_TAG_TO_PYTHON_MAP.get(decoded_value.tagSet)
                if py_type is int: value = int(decoded_value)
                elif py_type is bytes: value = bytes(decoded_value)
                elif py_type is type(None): value = None
                elif py_type is tuple: value = tuple(decoded_value)
                else: value = decoded_value

            except PyAsn1Error as e:
                raise ValueError(f"ASN.1 Error decoding obj {i+1} (OID: {oid_str}): {e}") from e
            except ValueError as e:
                raise ValueError(f"Error decoding obj {i+1} (OID: {oid_str}): {e}") from e

            objects.append(LMIObject(oid=oid_str, value=value))
        return objects

    def __repr__(self):
         return (f"{self.__class__.__name__}(pdu_type={self.pdu_type.name}, "
                 f"obj_count={self.object_count}, objects={self.objects})")


# --- LMI PDU Subclasses (Implementing specific headers) ---
class NonTrapPDU(LMIPDU):
    HEADER_LEN = 5 # Type, ReqID, ErrStatus, ErrIndex, ObjCount

    def __init__(self, pdu_type: LMIType, request_id: int, error_status: LMIErrorStatus, error_index: int, objects: List[LMIObject]):
        super().__init__(pdu_type, objects)
        if not (0 <= request_id <= 255): raise ValueError("Request ID must be 0-255")
        # Error index is 0 if no error, or 1..N for N objects
        if error_status != LMIErrorStatus.NO_ERROR and not (1 <= error_index <= self.object_count):
             raise ValueError(f"Error Index must be 1-{self.object_count} when error status is {error_status.name}")
        if error_status == LMIErrorStatus.NO_ERROR and error_index != 0:
             raise ValueError(f"Error Index must be 0 when error status is noError")

        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index

    def _pack_header(self) -> bytes:
        return struct.pack('>BBBBB',
                           self.pdu_type.value,
                           self.request_id,
                           self.error_status.value,
                           self.error_index,
                           self.object_count)

    def _get_header_len(self) -> int:
        return self.HEADER_LEN

    @classmethod
    def _unpack_from_stream(cls, stream: BytesIO) -> 'NonTrapPDU':
        header_bytes = stream.read(cls.HEADER_LEN)
        if len(header_bytes) < cls.HEADER_LEN:
            raise ValueError("LMI PDU too short for NonTrap header")

        pdu_type_val, req_id, err_stat_val, err_idx, obj_count = struct.unpack('>BBBBB', header_bytes)
        pdu_type = LMIType(pdu_type_val)
        try:
            error_status = LMIErrorStatus(err_stat_val)
        except ValueError:
             raise ValueError(f"Unknown LMI Error Status value: {err_stat_val}")

        target_cls = PDU_TYPE_TO_CLASS.get(pdu_type) # Use global map
        if not target_cls or not issubclass(target_cls, NonTrapPDU):
             # This case shouldn't happen if PDU_TYPE_TO_CLASS is correct
             raise TypeError(f"PDU type {pdu_type} resolved to incompatible class {target_cls}")

        objects = LMIPDU._static_unpack_objects(stream, obj_count)

        # Construct the final object based on type
        if target_cls == GetRequestPDU:
            return target_cls(request_id=req_id, oids_to_get=[o.oid for o in objects])
        elif target_cls == GetNextRequestPDU:
             return target_cls(request_id=req_id, oids_to_get_next=[o.oid for o in objects])
        elif target_cls == GetResponsePDU:
            return target_cls(request_id=req_id, error_status=error_status, error_index=err_idx, objects=objects)
        elif target_cls == SetRequestPDU:
            return target_cls(request_id=req_id, objects_to_set=objects)
        else: # Should not happen if map is correct
             raise TypeError(f"Cannot construct specific object for PDU type {pdu_type}")

    def __repr__(self):
         return (f"{self.__class__.__name__}(pdu_type={self.pdu_type.name}, req_id={self.request_id}, "
                 f"err_stat={self.error_status.name}, err_idx={self.error_index}, "
                 f"obj_count={self.object_count}, objects={self.objects})")


class TrapPDU(LMIPDU):
    HEADER_LEN = 4 # Type, GenericTrap, EnterpriseTrap, ObjCount

    def __init__(self, generic_trap: LMITrapType, enterprise_trap_type: int, objects: List[LMIObject]):
        super().__init__(LMIType.TRAP, objects)
        if not isinstance(generic_trap, LMITrapType): raise TypeError("generic_trap must be LMITrapType enum")
        # Enterprise trap type is an INTEGER, potentially large according to SNMPv1 Trap PDU
        self.generic_trap = generic_trap
        self.enterprise_trap_type = enterprise_trap_type

    def _pack_header(self) -> bytes:
         # Note: enterprise_trap_type might be larger than 1 byte in standard SNMP.
         # DXI LMI spec header shows 1 octet. Assuming it fits or truncates? Let's truncate.
         ent_trap_byte = self.enterprise_trap_type & 0xFF
         return struct.pack('>BBBB',
                            self.pdu_type.value,
                            self.generic_trap.value,
                            ent_trap_byte,
                            self.object_count)

    def _get_header_len(self) -> int:
        return self.HEADER_LEN

    @classmethod
    def _unpack_from_stream(cls, stream: BytesIO) -> 'TrapPDU':
        header_bytes = stream.read(cls.HEADER_LEN)
        if len(header_bytes) < cls.HEADER_LEN:
            raise ValueError("LMI PDU too short for Trap header")

        _pdu_type_val, gen_trap_val, ent_trap_val, obj_count = struct.unpack('>BBBB', header_bytes)
        try:
             generic_trap = LMITrapType(gen_trap_val)
        except ValueError:
              raise ValueError(f"Unknown LMI Generic Trap value: {gen_trap_val}")

        objects = LMIPDU._static_unpack_objects(stream, obj_count)
        return cls(generic_trap=generic_trap, enterprise_trap_type=ent_trap_val, objects=objects)

    def __repr__(self):
         ent_trap_str = f", ent_trap={self.enterprise_trap_type}" if self.generic_trap == LMITrapType.ENTERPRISE_SPECIFIC else ""
         return (f"{self.__class__.__name__}(pdu_type={self.pdu_type.name}, gen_trap={self.generic_trap.name}{ent_trap_str}, "
                 f"obj_count={self.object_count}, objects={self.objects})")


# --- Specific PDU Classes (Constructors) ---
class GetRequestPDU(NonTrapPDU):
     def __init__(self, request_id: int, oids_to_get: List[str]):
         objects = [LMIObject(oid=o, value=None) for o in oids_to_get]
         super().__init__(LMIType.GET_REQUEST, request_id, LMIErrorStatus.NO_ERROR, 0, objects)

class GetNextRequestPDU(NonTrapPDU):
     def __init__(self, request_id: int, oids_to_get_next: List[str]):
         objects = [LMIObject(oid=o, value=None) for o in oids_to_get_next]
         super().__init__(LMIType.GET_NEXT_REQUEST, request_id, LMIErrorStatus.NO_ERROR, 0, objects)

class GetResponsePDU(NonTrapPDU):
     def __init__(self, request_id: int, error_status: LMIErrorStatus, error_index: int, objects: List[LMIObject]):
         super().__init__(LMIType.GET_RESPONSE, request_id, error_status, error_index, objects)

class SetRequestPDU(NonTrapPDU):
     def __init__(self, request_id: int, objects_to_set: List[LMIObject]):
         for obj in objects_to_set:
             if obj.value is None:
                 raise ValueError(f"Object value cannot be None in SetRequest (OID: {obj.oid})")
         super().__init__(LMIType.SET_REQUEST, request_id, LMIErrorStatus.NO_ERROR, 0, objects_to_set)


# --- Global map for Unpacking ---
# Mapping from PDU type enum to specific class for unpacking delegation
PDU_TYPE_TO_CLASS: Dict[LMIType, type] = {
    LMIType.GET_REQUEST: GetRequestPDU,
    LMIType.GET_NEXT_REQUEST: GetNextRequestPDU,
    LMIType.GET_RESPONSE: GetResponsePDU,
    LMIType.SET_REQUEST: SetRequestPDU,
    LMIType.TRAP: TrapPDU,
}
