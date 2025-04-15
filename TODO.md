# TODO List for ATM DXI Python Implementation

This document outlines the remaining tasks and enhancements for the Python implementation of the ATM DXI Specification (v1.0, af-dxi-0014.000). The code is now split into modules (`dxi_constants.py`, `dxi_utils.py`, `dxi_frame.py`, `dxi_lmi.py`, `dxi_simulation.py`, `main.py`).

## Critical Implementations

*   **[Critical] LMI ASN.1/BER Decoding Debugging:**
    *   **Debug `LMIPDU._static_unpack_objects`:** Thoroughly debug the stream handling within this method (or its replacement). Ensure correct consumption of bytes after decoding variable-length fields (BER OID length, DXI OID bytes, BER Value TLV). Consider using `pyasn1.decoder.decode(substrate=True)` carefully.
    *   **Debug `decode_dxi_oid` Stream Interaction:** Verify that `decode_dxi_oid` correctly consumes bytes from the `BytesIO` stream provided to it during unpacking.
    *   **Test LMI Unpacking:** Create extensive unit tests for `LMIPDU.unpack` covering various PDU types, object types, edge cases, and potential malformed inputs.
*   **[Critical] AAL Processing Logic:**
    *   **DTE:** Implement AAL3/4 CPCS encapsulation for Modes 1b (AAL3/4) and Mode 2 (both AAL types) before passing payload to `DXIFrame`.
    *   **DTE:** Implement AAL3/4 CPCS decapsulation for received frames in Modes 1b (AAL3/4) and Mode 2.
    *   **DCE:** Implement AAL5 CPCS/SAR simulation (or interface) when processing DXI frames destined for AAL5 VCs (Modes 1a, 1b, 2).
    *   **DCE:** Implement AAL3/4 SAR simulation (or interface) when processing DXI frames destined for AAL3/4 VCs (Modes 1b, 2).
    *   **DCE:** Implement logic for Mode 2 AAL5 path: Strip AAL3/4 CPCS header/trailer from DXI payload before passing to simulated AAL5 processing.
    *   **DCE:** Implement reverse AAL processing when creating DXI frames from simulated network-side data.

## MIB and Management

*   **[Major] MIB Implementation (DCE):**
    *   Implement `GetNextRequest` logic (requires ordered MIB traversal).
    *   Implement `SetRequest` logic (write access, validation, error handling based on ASN.1 types).
    *   Implement a more robust MIB storage mechanism in the `DCE` class (beyond simple dict).
    *   Parse and represent the MIB definitions from Annex B (using the ASN.1 library eventually).
    *   Implement logic for `atmDxiConfTable` (Mode setting).
    *   Implement logic for `atmDxiDFAConfTable` (AAL type per DFA).
*   **[Major] MIB-Centric Indexing / Proxy Logic (DTE):**
    *   Implement the IfIndex assignment logic in the DTE for its own interfaces and the proxied DCE interfaces (as described in Section 4.1.2).
    *   Modify DTE's LMI request generation to potentially include the correct proxied `IfIndex`.
    *   Modify DTE's handling of LMI responses to map them back to the correct proxied interface context if needed for higher-level management.
*   **[Enhancement] SNMP/ILMI Proxy Simulation (DTE):**
    *   Add placeholder classes/logic in the DTE to simulate receiving SNMP/ILMI requests.
    *   Implement the decision logic in the DTE proxy to determine if a request targets the DTE itself or requires forwarding an LMI request to the DCE.
    *   Simulate forwarding Traps received via LMI from DCE up to simulated SNMP/ILMI managers.

## Framing and Core Logic

*   **[Enhancement] HDLC Bit Stuffing/Destuffing:**
    *   Implement optional bit stuffing/destuffing functions to simulate the zero-insertion/removal done at a lower layer. Modify `DXIFrame.pack`/`unpack` to use these.
*   **[Refinement] Header Validation:**
    *   Add stricter checks in `DXIFrame.unpack` for reserved bits and fixed bits according to the specification figures.
*   **[Refinement] LMI Error Handling:**
    *   Implement detailed LMI error status generation (e.g., `tooBig` based on actual buffer/MTU limits, `badValue` based on ASN.1 type/constraint mismatch).
    *   Ensure correct `ErrorIndex` values are returned in `GetResponsePDU`.
*   **[Enhancement] Configuration:**
    *   Add ways to configure DTE/DCE mode, simulated buffer sizes, MIB values, etc. (Potentially via config files or command-line args).
*   **[Enhancement] Logging:**
    *   Replace `print` statements with a proper logging framework (e.g., Python's `logging` module) across all modules.

## Testing

*   **[Critical] LMI Encoding Unit Tests:** Add unit tests specifically for `encode_dxi_oid`, `encode_ber_length`, `encode_asn1_value` (in `dxi_utils.py`) and the `LMIPDU.pack` methods for all PDU types (in `dxi_lmi.py`).
*   **[Critical] Unit Tests:**
    *   Test `DXIFrame` pack/unpack (in `dxi_frame.py`).
    *   Test `DXIFrame` FCS calculation/validation.
    *   Test DFA <-> VPI/VCI mapping functions (in `dxi_utils.py`).
    *   *(Post-Debug)* Test LMI PDU unpack methods thoroughly (in `dxi_lmi.py`).
*   **[Major] Integration Tests:**
    *   Test DTE <-> DCE data frame exchange using classes from `dxi_simulation.py`.
    *   *(Post-Debug)* Test DTE <-> DCE LMI Get/GetNext/Set/Response sequence.
    *   *(Post-Debug)* Test DCE -> DTE Trap transmission.

## Documentation & Refinement

*   **[Enhancement] Docstrings:** Add/update comprehensive docstrings to all classes and methods in all files.
*   **[Enhancement] README:** Create/Update README with detailed usage, module descriptions, limitations, dependencies (`pyasn1`, `crcmod`), and setup instructions.
*   **[Enhancement] Architecture:** Add a brief diagram or description of the module structure and dependencies.
*   **[Refinement] Imports:** Ensure imports are clean and efficient across modules.
