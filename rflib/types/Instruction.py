from rflib.defs import *
from TLV import *
from bson.binary import Binary

# instruction Type Variables ('Enum')
RFIT_METER = 1              # Meter id
RFIT_APPLY_ACTIONS = 2      # Apply actions
RFIT_CLEAR_ACTIONS = 3      # Clear actions
RFIT_WRITE_ACTIONS = 4      # Write actions
RFIT_WRITE_METADATA = 5     # Write metadata
RFIT_GO_TABLE = 6           # Go to table

typeStrings = {
            RFIT_METER : "RFIT_METER",
            RFIT_APPLY_ACTIONS : "RFIT_APPLY_ACTIONS",
            RFIT_CLEAR_ACTIONS : "RFIT_CLEAR_ACTIONS",
            RFIT_WRITE_ACTIONS : "RFIT_WRITE_ACTIONS",
            RFIT_WRITE_METADATA : "RFIT_WRITE_METADATA",
            RFIT_GO_TABLE : "RFIT_GO_TABLE",
        }

class Instruction(TLV):
    def __init__(self, instructionType=None, value=None):
        super(Instruction, self).__init__(instructionType, self.type_to_bin(instructionType, value))

    def __str__(self):
        return "%s : %s" % (self.type_to_str(self._type), self.get_value())

    @classmethod
    def METER(cls, meter_id):
        return cls(RFIT_METER, meter_id)

    @classmethod
    def APPLY_ACTIONS(cls):
        return cls(RFIT_APPLY_ACTIONS, None)

    @classmethod
    def CLEAR_ACTIONS(cls):
        return cls(RFIT_CLEAR_ACTIONS, None)

    @classmethod
    def WRITE_ACTIONS(cls):
        return cls(RFIT_WRITE_ACTIONS, None)

    #TODO:  create TLV function to convert (metadata,metadata_mask) to bin
    @classmethod
    def WRITE_METADATA(cls, metadata, metadata_mask):
        return cls(RFIT_WRITE_METADATA, (metadata,metadata_mask) )

    @classmethod
    def GO_TABLE(cls, next_table_id):
        return cls(RFIT_GO_TABLE, next_table_id)

    @classmethod
    def from_dict(cls, dic):
        ac = cls()
        ac._type = dic['type']
        ac._value = dic['value']
        return ac

    @staticmethod
    def type_to_bin(instructionType, value):
        if instructionType in (RFIT_METER, RFIT_GO_TABLE):
            return int_to_bin(value, 32)
        elif instructionType in (RFIT_APPLY_ACTIONS, RFIT_CLEAR_ACTIONS, RFIT_WRITE_ACTIONS):
            return ''
        else:
            return None

    @staticmethod
    def type_to_str(instructionType):
        if instructionType in typeStrings:
            return typeStrings[instructionType]
        else:
            return str(instructionType)

    def get_value(self):
        if self._type in (RFIT_METER, RFIT_GO_TABLE):
            return bin_to_int(self._value)
        elif self._type in (RFIT_APPLY_ACTIONS, RFIT_CLEAR_ACTIONS, RFIT_WRITE_ACTIONS):
            return None
        else:
            return None

    def set_value(self, value):
        self._value = Binary(self.type_to_bin(self._type, value), 0)
