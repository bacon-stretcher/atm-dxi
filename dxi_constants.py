import enum

# --- Constants ---
DXI_FLAG = 0x7E

# --- Enums ---
class DXIMode(enum.Enum):
    MODE_1A = 1
    MODE_1B = 2
    MODE_2  = 3

class LMIType(enum.Enum):
    GET_REQUEST = 0
    GET_NEXT_REQUEST = 1
    GET_RESPONSE = 2
    SET_REQUEST = 3
    TRAP = 4

class LMIErrorStatus(enum.Enum):
    NO_ERROR = 0
    TOO_BIG = 1
    NO_SUCH_NAME = 2
    BAD_VALUE = 3
    GEN_ERR = 5

class LMITrapType(enum.Enum):
    COLD_START = 0
    WARM_START = 1
    LINK_DOWN = 2
    LINK_UP = 3
    ENTERPRISE_SPECIFIC = 6

class AALType(enum.Enum):
    UNKNOWN = 1
    NONE = 2
    AAL34 = 3
    AAL5 = 4
