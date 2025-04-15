#!/usr/bin/env python3

from dxi_constants import DXIMode, LMITrapType
from dxi_simulation import DTE, DCE
from dxi_lmi import LMIObject # Needed for creating trap objects
from dxi_utils import vpivci_to_dfa1 # Needed for example

# --- Example Usage ---
if __name__ == "__main__":
    print("--- Mode 1b Example ---")
    my_dte = DTE(DXIMode.MODE_1B)
    my_dce = DCE(DXIMode.MODE_1B)

    # DTE sends data
    sdu_data = b"Data for DTE->DCE"
    vpi1, vci1 = 1, 32; dfa1 = vpivci_to_dfa1(vpi1, vci1)
    print(f"DTE: Sending data for VPI={vpi1}, VCI={vci1} (DFA={dfa1})")
    dxi_frame_bytes_1 = my_dte.create_data_frame(sdu_data, dfa=dfa1, clp=0)
    print(f"DTE->DCE Data Frame Bytes: {dxi_frame_bytes_1.hex()}")
    try:
        dfa_rcvd, clp_rcvd, payload_rcvd = my_dce.process_received_frame(dxi_frame_bytes_1)
        print(f"DCE Processed Data OK: DFA={dfa_rcvd}, CLP={clp_rcvd}, Payload='{payload_rcvd.decode()}'")
    except Exception as e: print(f"DCE Error processing data: {e}")

    print("\n--- LMI Example (GetRequest/Response) ---")
    oids_to_query = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.353.2.1.1.0", "1.3.6.1.4.1.353.2.2.1.2.99"] # Last one should fail
    print(f"DTE: Creating LMI GetRequest (ReqID {my_dte.lmi_request_id+1}) for OIDs: {oids_to_query}")
    lmi_req_frame_bytes = my_dte.create_lmi_get_request(oids_to_query)
    print(f"DTE->DCE LMI Req Frame Bytes: {lmi_req_frame_bytes.hex()}")

    try:
        lmi_req_pdu = my_dce.process_received_frame(lmi_req_frame_bytes)
        if isinstance(lmi_req_pdu, LMIPDU): # Check if it's an LMI PDU
            lmi_resp_frame_bytes = my_dce.create_lmi_response_frame(lmi_req_pdu)
            print(f"DCE->DTE LMI Resp Frame Bytes: {lmi_resp_frame_bytes.hex()}")
            try:
                 lmi_resp_pdu = my_dte.process_received_frame(lmi_resp_frame_bytes)
                 print(f"DTE Received LMI Response OK: {lmi_resp_pdu}")
            except Exception as e: print(f"DTE Error processing LMI Resp: {e}")
        else: # Should be Tuple[int, int, bytes] if data
            print(f"DCE: Expected LMI PDU but got data frame: {lmi_req_pdu}")
    except Exception as e: print(f"DCE Error processing LMI Req: {e}")

    print("\n--- LMI Example (Trap) ---")
    # Simulate DCE sending a linkDown trap
    print("DCE: Creating linkDown trap")
    # Use ifIndex.1 (1.3.6.1.2.1.2.2.1.1.1) and ifOperStatus.1 (1.3.6.1.2.1.2.2.1.8.1)
    if_index_obj = LMIObject(oid="1.3.6.1.2.1.2.2.1.1.1", value=1)
    if_oper_status_obj = LMIObject(oid="1.3.6.1.2.1.2.2.1.8.1", value=2) # 2=down
    trap_objects = [if_index_obj, if_oper_status_obj]
    trap_frame_bytes = my_dce.create_trap_frame(LMITrapType.LINK_DOWN, trap_objects)
    print(f"DCE->DTE LMI Trap Frame Bytes: {trap_frame_bytes.hex()}")
    try:
        trap_pdu = my_dte.process_received_frame(trap_frame_bytes)
        print(f"DTE Received LMI Trap OK: {trap_pdu}")
    except Exception as e: print(f"DTE Error processing LMI Trap: {e}")


    print("\n*** NOTE: LMI Unpacking logic requires further debugging (stream handling) ***")
    # You might still see errors here until the unpacking is fully resolved.
