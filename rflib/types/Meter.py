from rflib.defs import *
from TLV import *
from bson.binary import Binary

# meter Type Variables ('Enum')
RFMT_TYPE = 1    # Meter type
RFMT_RATE = 2      # Meter rate
RFMT_BURST = 3  # Meter burst_rate
RFMT_PREC_LEVEL = 4 # meter prec level
RFMT_EXP = 5 # meter experimenter

typeStrings = {
            RFMT_TYPE : "RFMT_TYPE",
            RFMT_RATE : "RFMT_RATE",
            RFMT_BURST : "RFMT_BURST",
            RFMT_PREC_LEVEL : "RFMT_PREC_LEVEL",
            RFMT_EXP : "RFMT_EXP"
        }

class Meter(TLV):
    _TYPE_DROP = 1
    _TYPE_DSCP_REMARK = 2
    _TYPE_EXPERIMENTER = 3
    
    def __init__(self, meterType=None, value=None):
        super(Meter, self).__init__(meterType, self.type_to_bin(meterType, value))

    def __str__(self):
        return "%s : %s" % (self.type_to_str(self._type), self.get_value())

    @classmethod
    def SET_METER_TYPE(cls, meter_type):
        return cls(RFMT_TYPE, meter_type)

    @classmethod
    def SET_RATE(cls, meter_rate):
        return cls(RFMT_RATE, meter_rate)

    @classmethod
    def SET_BURST(cls, meter_burst_size):
        return cls(RFMT_BURST, meter_burst_size)

    @classmethod
    def SET_PREC_LEVEL(cls, meter_prec_level):
        return cls(RFMT_PREC_LEVEL, meter_prec_level)

    @classmethod
    def SET_EXP(cls, meter_exp):
        return cls(RFMT_EXP, meter_exp)

    @classmethod
    def from_dict(cls, dic):
        ac = cls()
        ac._type = dic['type']
        ac._value = dic['value']
        return ac

    @staticmethod
    def type_to_bin(meterType, value):
        if meterType in (RFMT_TYPE, RFMT_RATE, RFMT_BURST, RFMT_PREC_LEVEL, RFMT_EXP):
            return int_to_bin(value, 32)
        else:
            return None

    @staticmethod
    def type_to_str(meterType):
        if meterType in typeStrings:
            return typeStrings[meterType]
        else:
            return str(meterType)

    def get_value(self):
        if self._type in (RFMT_TYPE, RFMT_RATE, RFMT_BURST, RFMT_PREC_LEVEL, RFMT_EXP):
            return bin_to_int(self._value)
        else:
            return None

    def set_value(self, value):
        self._value = Binary(self.type_to_bin(self._type, value), 0)
