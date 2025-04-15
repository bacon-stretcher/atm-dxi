from typing import List, Tuple, Union, Dict, Any

# Import pyasn1 types and errors for exception handling if needed
from pyasn1.error import PyAsn1Error

from dxi_constants import DXIMode, LMIType, LMITrapType, AALType, LMIErrorStatus
from dxi_frame import DXIFrame
from dxi_lmi import (
    LMIPDU, LMIObject, NonTrapPDU, TrapPDU,
    GetRequestPDU, GetNextRequestPDU, GetResponsePDU, SetRequestPDU
)
from dxi_utils import dfa1_to_vpivci, dfa2_to_vpivci # Only need mapping here

class DTE:
    """Simulated DTE."""
    def __init__(self, mode: DXIMode):
        self.mode = mode
        self.lmi_request_id = 0

    def _get_next_lmi_request_id(self) -> int:
        self.lmi_request_id = (self.lmi_request_id + 1) % 256
        return self.lmi_request_id

    def create_data_frame(self, dte_sdu: bytes, dfa: int, clp: int) -> bytes:
        """Encapsulates DTE SDU into a DXI frame."""
        payload = dte_sdu # Simplification - assumes caller handles AAL3/4 if needed
        # print(f"DTE: Creating frame for DFA {dfa}, CLP {clp}, Mode {self.mode.name}")
        frame = DXIFrame(self.mode, dfa, clp, payload, cn=0)
        return frame.pack()

    def create_lmi_get_request(self, oids: List[str]) -> bytes:
        """Creates an LMI GetRequest frame."""
        req_id = self._get_next_lmi_request_id()
        # print(f"DTE: Creating LMI GetRequest (ReqID {req_id}) for OIDs: {oids}")
        pdu = GetRequestPDU(req_id, oids)
        pdu_bytes = pdu.pack()
        frame = DXIFrame(self.mode, dfa=0, clp=0, payload=pdu_bytes, cn=0)
        return frame.pack()

    # Add create_lmi_set_request, create_lmi_getnext_request if needed

    def process_received_frame(self, frame_bytes: bytes) -> Union[Tuple[int, int, bytes], LMIPDU]:
        """Processes a frame received from DCE (data or LMI response/trap)."""
        # print(f"DTE: Received frame ({len(frame_bytes)} bytes)")
        try:
            frame = DXIFrame.unpack(frame_bytes, self.mode)
            # print(f"DTE: Unpacked frame: {frame}")
            if frame.dfa == 0: # LMI Frame
                # print("DTE: Frame is LMI")
                # Use the LMIPDU.unpack method which handles delegation
                lmi_pdu = LMIPDU.unpack(frame.payload)
                # print(f"DTE: Unpacked LMI PDU: {lmi_pdu}")
                return lmi_pdu
            else: # Data Frame
                 # print(f"DTE: Frame is Data (DFA {frame.dfa}, CLP {frame.clp}, CN {frame.cn})")
                 dte_sdu = frame.payload # Simplification
                 return (frame.dfa, frame.clp, dte_sdu)
        except (ValueError, PyAsn1Error, NotImplementedError) as e:
            # Catch errors from frame unpacking or LMI unpacking
            print(f"DTE: Error processing frame: {e}")
            raise


class DCE:
    """Simulated DCE."""
    def __init__(self, mode: DXIMode):
        self.mode = mode
        # Simulated MIB using native Python types
        self.mib: Dict[str, Any] = {
            "1.3.6.1.4.1.353.2.1.1.0": self.mode.value, # atmDxiConfMode (Integer)
            "1.3.6.1.4.1.353.2.2.1.2.10": AALType.AAL5.value, # atmDxiDFAConfAALType for DFA=10 (Integer)
            "1.3.6.1.4.1.353.2.2.1.2.20": AALType.AAL34.value,# atmDxiDFAConfAALType for DFA=20 (Integer)
            "1.3.6.1.2.1.1.1.0": b"DXI Interface 1", # ifDescr (OctetString/bytes)
            "1.3.6.1.2.1.1.3.0": 6, # ifType (Integer) = ethernetCsmacd (Example)
             # Example using OID value type (represented as string here for simplicity in MIB dict)
            "1.3.6.1.4.1.353.5.1.0": "1.3.6.1.4.1.353.1", # Example OID value
        }

    def process_received_frame(self, frame_bytes: bytes) -> Union[Tuple[int, int, bytes], LMIPDU]:
        """Processes a frame received from DTE (data or LMI request)."""
        # print(f"DCE: Received frame ({len(frame_bytes)} bytes)")
        try:
            frame = DXIFrame.unpack(frame_bytes, self.mode)
            # print(f"DCE: Unpacked frame: {frame}")
            if frame.dfa == 0: # LMI Frame
                # print("DCE: Frame is LMI")
                lmi_pdu = LMIPDU.unpack(frame.payload)
                # print(f"DCE: Unpacked LMI PDU: {lmi_pdu}")
                return lmi_pdu # DCE needs to process this
            else: # Data Frame
                # print(f"DCE: Frame is Data (DFA {frame.dfa}, CLP {frame.clp})")
                payload_to_aal = frame.payload
                # Map DFA to VPI/VCI
                if self.mode != DXIMode.MODE_2:
                    vpi, vci = dfa1_to_vpivci(frame.dfa)
                else:
                    vpi, vci = dfa2_to_vpivci(frame.dfa)
                # print(f"DCE: Mapped DFA {frame.dfa} to VPI={vpi}, VCI={vci}")
                return (frame.dfa, frame.clp, payload_to_aal)
        except (ValueError, PyAsn1Error, NotImplementedError) as e:
            print(f"DCE: Error processing frame: {e}")
            raise

    def _handle_lmi_request(self, request_pdu: NonTrapPDU) -> GetResponsePDU:
         """Handles Get, GetNext, Set requests and returns a GetResponsePDU."""
         # print(f"DCE: Handling LMI Request {request_pdu.request_id} ({request_pdu.pdu_type.name})")
         response_objects = []
         error_status = LMIErrorStatus.NO_ERROR
         error_index = 0

         if request_pdu.pdu_type == LMIType.GET_REQUEST:
            for i, req_obj in enumerate(request_pdu.objects):
                if req_obj.oid in self.mib:
                     val = self.mib[req_obj.oid]
                     response_objects.append(LMIObject(oid=req_obj.oid, value=val))
                else:
                    # print(f"DCE: OID not found: {req_obj.oid}")
                    error_status = LMIErrorStatus.NO_SUCH_NAME; error_index = i + 1
                    # Return original object list in case of error in GetRequest (SNMPv1 style)
                    response_objects = [LMIObject(o.oid, None) for o in request_pdu.objects]
                    break
         elif request_pdu.pdu_type == LMIType.GET_NEXT_REQUEST:
              print("DCE: GetNextRequest handling not implemented")
              error_status = LMIErrorStatus.GEN_ERR; error_index = 1
              response_objects = [LMIObject(o.oid, None) for o in request_pdu.objects]
         elif request_pdu.pdu_type == LMIType.SET_REQUEST:
              print("DCE: SetRequest handling not implemented")
              error_status = LMIErrorStatus.GEN_ERR; error_index = 1 # Or noSuchName/badValue
              response_objects = request_pdu.objects # Return original objects+values
         else:
              print(f"DCE: Unexpected PDU type in _handle_lmi_request: {request_pdu.pdu_type}")
              error_status = LMIErrorStatus.GEN_ERR; error_index = 0
              response_objects = [] # No objects for genErr on unknown type

         return GetResponsePDU(request_pdu.request_id, error_status, error_index, response_objects)

    def create_lmi_response_frame(self, request_pdu: LMIPDU) -> bytes:
        """Creates an LMI GetResponse frame based on a request PDU."""
        if isinstance(request_pdu, NonTrapPDU):
            resp_pdu = self._handle_lmi_request(request_pdu)
        else:
            print(f"DCE: Cannot generate response for PDU type {request_pdu.pdu_type}")
            return b''

        # print(f"DCE: Creating LMI Response Frame: {resp_pdu}")
        pdu_bytes = resp_pdu.pack()
        frame = DXIFrame(self.mode, dfa=0, clp=0, payload=pdu_bytes, cn=0)
        return frame.pack()

    def create_trap_frame(self, trap_type: LMITrapType, trap_objects: List[LMIObject], enterprise_code: int = 0) -> bytes:
         """Creates an LMI Trap frame."""
         # print(f"DCE: Creating LMI Trap Frame: Type={trap_type.name}")
         if trap_type == LMITrapType.ENTERPRISE_SPECIFIC:
              # DXI Spec 3.2.3.4: First Object ID is atmDxiEnterprise.0, Value identifies enterprise OID
              # atmDxiEnterprise OBJECT IDENTIFIER ::= { atmForum 4 } -> 1.3.6.1.4.1.353.4
              # The object is atmDxiEnterprise.0 -> "1.3.6.1.4.1.353.4.0"
              # The VALUE of this object is the specific enterprise OID, e.g., "1.3.6.1.4.1.9" for Cisco
              your_enterprise_oid = "1.3.6.1.4.1.353" # Example: Use ATM Forum itself
              enterprise_oid_obj = LMIObject(oid="1.3.6.1.4.1.353.4.0", value=your_enterprise_oid)
              final_objects = [enterprise_oid_obj] + trap_objects
              pdu = TrapPDU(trap_type, enterprise_code, final_objects)
         else:
              pdu = TrapPDU(trap_type, 0, trap_objects) # Enterprise code 0 for standard traps

         pdu_bytes = pdu.pack()
         frame = DXIFrame(self.mode, dfa=0, clp=0, payload=pdu_bytes, cn=0)
         return frame.pack()

    def create_data_frame(self, dte_sdu: bytes, dfa: int, cn: int = 0) -> bytes:
        """Creates DXI frame from simulated network side towards DTE."""
        payload = dte_sdu # Simplification
        # print(f"DCE: Creating frame for DTE (DFA {dfa}, CN {cn}), Mode {self.mode.name}")
        # CLP bit from DCE to DTE is always set to zero
        frame = DXIFrame(self.mode, dfa, clp=0, payload=payload, cn=cn)
        return frame.pack()
