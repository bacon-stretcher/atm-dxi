import struct
from typing import Optional

from dxi_constants import DXIMode, DXI_FLAG
from dxi_utils import crc16_func, crc32_func

class DXIFrame:
    """Represents an ATM DXI Frame (Modes 1a, 1b, 2)."""
    def __init__(self, mode: DXIMode, dfa: int, clp: int, payload: bytes, cn: int = 0):
        if mode in (DXIMode.MODE_1A, DXIMode.MODE_1B):
            if not (0 <= dfa <= 1023): raise ValueError("Mode 1 DFA out of range (0-1023)")
            self.header_len = 2; self.fcs_len = 2; self.max_dfa = 1023; self._crc_func = crc16_func
        elif mode == DXIMode.MODE_2:
            if not (0 <= dfa <= 0xFFFFFF): raise ValueError("Mode 2 DFA out of range (0-16777215)")
            self.header_len = 4; self.fcs_len = 4; self.max_dfa = 0xFFFFFF; self._crc_func = crc32_func
        else: raise ValueError("Invalid DXI Mode")
        if not (0 <= clp <= 1): raise ValueError("CLP must be 0 or 1")
        if not (0 <= cn <= 1): raise ValueError("CN must be 0 or 1")
        self.mode = mode; self.dfa = dfa; self.clp = clp; self.cn = cn; self.payload = payload; self.fcs: Optional[int] = None

    def _build_header(self) -> bytes:
        if self.mode in (DXIMode.MODE_1A, DXIMode.MODE_1B):
            o1 = ((self.dfa >> 6) & 0x0F) << 3
            o2 = ((self.dfa >> 0) & 0x3F) << 2; o2 |= (self.cn & 0x01) << 5; o2 |= (self.clp & 0x01) << 1; o2 |= 1
            return struct.pack('>BB', o1, o2)
        else: # Mode 2
            o1 = ((self.dfa >> 18) & 0x3F) << 2
            o2 = ((self.dfa >> 16) & 0x03) << 6; o2 |= (self.cn & 0x01) << 5; o2 |= (self.clp & 0x01) << 1
            o3 = ((self.dfa >> 7) & 0x7F) << 1
            o4 = (self.dfa & 0x7F) << 1; o4 |= 1
            return struct.pack('>BBBB', o1, o2, o3, o4)

    def pack(self) -> bytes:
        header = self._build_header()
        data_for_fcs = header + self.payload
        self.fcs = self._crc_func(data_for_fcs)
        fcs_bytes = self.fcs.to_bytes(self.fcs_len, byteorder='little')
        frame = bytes([DXI_FLAG]) + header + self.payload + fcs_bytes + bytes([DXI_FLAG])
        return frame # Note: Bit stuffing not implemented here

    @classmethod
    def unpack(cls, frame_bytes: bytes, expected_mode: DXIMode) -> 'DXIFrame':
        if not frame_bytes.startswith(bytes([DXI_FLAG])) or not frame_bytes.endswith(bytes([DXI_FLAG])): raise ValueError("Frame missing flags")
        content = frame_bytes[1:-1]
        if expected_mode in (DXIMode.MODE_1A, DXIMode.MODE_1B): header_len, fcs_len, crc_func = 2, 2, crc16_func
        elif expected_mode == DXIMode.MODE_2: header_len, fcs_len, crc_func = 4, 4, crc32_func
        else: raise ValueError("Invalid DXI Mode for unpacking")
        if len(content) < header_len + fcs_len: raise ValueError("Frame content too short")
        header = content[:header_len]; payload = content[header_len:-fcs_len]; fcs_received_bytes = content[-fcs_len:]
        fcs_received = int.from_bytes(fcs_received_bytes, byteorder='little')
        data_for_fcs = header + payload; fcs_calculated = crc_func(data_for_fcs)
        if fcs_received != fcs_calculated: raise ValueError(f"FCS Mismatch. Rcvd: {fcs_received:x}, Calc: {fcs_calculated:x}")

        if expected_mode in (DXIMode.MODE_1A, DXIMode.MODE_1B):
            o1, o2 = struct.unpack('>BB', header)
            dfa = (((o1 >> 3) & 0x0F) << 6) | (((o2 >> 2) & 0x3F) << 0)
            cn = (o2 >> 5) & 0x01; clp = (o2 >> 1) & 0x01
        else: # Mode 2
            o1, o2, o3, o4 = struct.unpack('>BBBB', header)
            dfa = (((o1 >> 2) & 0x3F) << 18) | (((o2 >> 6) & 0x03) << 16) | (((o3 >> 1) & 0x7F) << 7) | (((o4 >> 1) & 0x7F) << 0)
            cn = (o2 >> 5) & 0x01; clp = (o2 >> 1) & 0x01
        return cls(expected_mode, dfa, clp, payload, cn)

    def __repr__(self):
        fcs_hex = f"{self.fcs:x}" if self.fcs is not None else "N/A"
        return (f"DXIFrame(mode={self.mode.name}, dfa={self.dfa}, clp={self.clp}, "
                f"cn={self.cn}, payload_len={len(self.payload)}, fcs={fcs_hex} (calc))")
