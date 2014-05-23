from rflib.defs import *
from TLV import *
from bson.binary import Binary

# Group Type Variables ('Enum')
RFGP_WEIGHT = 1 # Bucket group weight
RFGP_WATCH_PORT = 2    # Group FF WATCH_PORT 
RFGP_WATCH_GROUP = 3    # Group FF WATCH_GROUP
RFGP_ACTIONS = 4    # bucket group actions

typeStrings = {
            RFGP_WEIGHT : "RFGP_WEIGHT",
            RFGP_WATCH_PORT : "RFGP_WATCH_PORT",
            RFGP_WATCH_GROUP : "RFGP_WATCH_GROUP",
            RFGP_ACTIONS : "RFGP_ACTIONS"
        }

class Group(TLV):
    def __init__(self, GroupType=None, value=None):
        super(Group, self).__init__(GroupType, self.type_to_bin(GroupType, value))

    def __str__(self):
        return "%s : %s" % (self.type_to_str(self._type), self.get_value())

    @classmethod
    def SET_WEIGHT(cls, bucket_weight):
        return cls(RFGP_WEIGHT, bucket_weight)

    @classmethod
    def SET_WATCH_PORT(cls, watch_port):
        return cls(RFGP_WATCH_PORT, watch_port)

    @classmethod
    def SET_WATCH_GROUP(cls, watch_group):
        return cls(RFGP_WATCH_GROUP, watch_group)

    @classmethod
    def SET_ACTIONS(cls, bucket_actions_id):
        return cls(RFGP_ACTIONS, bucket_actions_id)
    
    @classmethod
    def from_dict(cls, dic):
        ac = cls()
        ac._type = dic['type']
        ac._value = dic['value']
        return ac

    @staticmethod
    def type_to_bin(GroupType, value):
        if GroupType in (RFGP_WEIGHT, RFGP_WATCH_PORT, RFGP_WATCH_GROUP, RFGP_ACTIONS):
            return int_to_bin(value, 32)
        else:
            return None

    @staticmethod
    def type_to_str(GroupType):
        if GroupType in typeStrings:
            return typeStrings[GroupType]
        else:
            return str(GroupType)

    def get_value(self):
        if self._type in (RFGP_WEIGHT, RFGP_WATCH_PORT, RFGP_WATCH_GROUP, RFGP_ACTIONS):
            return bin_to_int(self._value)
        else:
            return None

    def set_value(self, value):
        self._value = Binary(self.type_to_bin(self._type, value), 0)
