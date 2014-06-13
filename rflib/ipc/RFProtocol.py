import bson

from rflib.types.Match import Match
from rflib.types.Action import Action
from rflib.types.Option import Option
from rflib.types.Meter import Meter
from rflib.types.Instruction import Instruction
from MongoIPC import MongoIPCMessage

format_id = lambda dp_id: hex(dp_id).rstrip('L')

PORT_REGISTER = 0
PORT_CONFIG = 1
DATAPATH_PORT_REGISTER = 2
DATAPATH_DOWN = 3
VIRTUAL_PLANE_MAP = 4
DATA_PLANE_MAP = 5
ROUTE_MOD = 6
CONTROLLER_REGISTER = 7
ELECT_MASTER = 8
DATA_PLANE_LINK = 9
METER_MOD = 10
GROUP_MOD = 11
INTERFACE_REGISTER = 12


class PortRegister(MongoIPCMessage):
    def __init__(self, vm_id=None, vm_port=None, hwaddress=None):
        self.set_vm_id(vm_id)
        self.set_vm_port(vm_port)
        self.set_hwaddress(hwaddress)

    def get_type(self):
        return PORT_REGISTER

    def get_vm_id(self):
        return self.vm_id

    def set_vm_id(self, vm_id):
        vm_id = 0 if vm_id is None else vm_id
        try:
            self.vm_id = int(vm_id)
        except:
            self.vm_id = 0

    def get_vm_port(self):
        return self.vm_port

    def set_vm_port(self, vm_port):
        vm_port = 0 if vm_port is None else vm_port
        try:
            self.vm_port = int(vm_port)
        except:
            self.vm_port = 0

    def get_hwaddress(self):
        return self.hwaddress

    def set_hwaddress(self, hwaddress):
        hwaddress = "" if hwaddress is None else hwaddress
        try:
            self.hwaddress = str(hwaddress)
        except:
            self.hwaddress = ""

    def from_dict(self, data):
        self.set_vm_id(data["vm_id"])
        self.set_vm_port(data["vm_port"])
        self.set_hwaddress(data["hwaddress"])

    def to_dict(self):
        data = {}
        data["vm_id"] = str(self.get_vm_id())
        data["vm_port"] = str(self.get_vm_port())
        data["hwaddress"] = str(self.get_hwaddress())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "PortRegister\n"
        s += "  vm_id: " + format_id(self.get_vm_id()) + "\n"
        s += "  vm_port: " + str(self.get_vm_port()) + "\n"
        s += "  hwaddress: " + str(self.get_hwaddress()) + "\n"
        return s


class InterfaceRegister(MongoIPCMessage):
    def __init__(self, name=None, vm_id=None, vm_port=None, address=None, netmask=None, hwaddress=None):
        self.set_name(name)
        self.set_vm_id(vm_id)
        self.set_vm_port(vm_port)
        self.set_address(address)
        self.set_netmask(netmask)
        self.set_hwaddress(hwaddress)

    def get_type(self):
        return INTERFACE_REGISTER

    def get_name(self):
        return self.name

    def set_name(self, name):
        name = "" if name is None else name
        try:
            self.name = str(name)
        except:
            self.name = ""

    def get_vm_id(self):
        return self.vm_id

    def set_vm_id(self, vm_id):
        vm_id = 0 if vm_id is None else vm_id
        try:
            self.vm_id = int(vm_id)
        except:
            self.vm_id = 0

    def get_vm_port(self):
        return self.vm_port

    def set_vm_port(self, vm_port):
        vm_port = 0 if vm_port is None else vm_port
        try:
            self.vm_port = int(vm_port)
        except:
            self.vm_port = 0

    def get_address(self):
        return self.address

    def set_address(self, address):
        address = "" if address is None else address
        try:
            self.address = str(address)
        except:
            self.address = ""

    def get_netmask(self):
        return self.netmask

    def set_netmask(self, netmask):
        netmask = "" if netmask is None else netmask
        try:
            self.netmask = str(netmask)
        except:
            self.netmask = ""

    def get_hwaddress(self):
        return self.hwaddress

    def set_hwaddress(self, hwaddress):
        hwaddress = "" if hwaddress is None else hwaddress
        try:
            self.hwaddress = str(hwaddress)
        except:
            self.hwaddress = ""

    def from_dict(self, data):
        self.set_name(data["name"])
        self.set_vm_id(data["vm_id"])
        self.set_vm_port(data["vm_port"])
        self.set_address(data["address"])
        self.set_netmask(data["netmask"])
        self.set_hwaddress(data["hwaddress"])

    def to_dict(self):
        data = {}
        data["name"] = str(self.get_name())
        data["vm_id"] = str(self.get_vm_id())
        data["vm_port"] = str(self.get_vm_port())
        data["address"] = str(self.get_address())
        data["netmask"] = str(self.get_netmask())
        data["hwaddress"] = str(self.get_hwaddress())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "InterfaceRegister\n"
        s += "  name: " + str(self.get_name()) + "\n"
        s += "  vm_id: " + str(self.get_vm_id()) + "\n"
        s += "  vm_port: " + str(self.get_vm_port()) + "\n"
        s += "  address: " + str(self.get_address()) + "\n"
        s += "  netmask: " + str(self.get_netmask()) + "\n"
        s += "  hwaddress: " + str(self.get_hwaddress()) + "\n"
        return s

class PortConfig(MongoIPCMessage):
    def __init__(self, vm_id=None, vm_port=None, operation_id=None):
        self.set_vm_id(vm_id)
        self.set_vm_port(vm_port)
        self.set_operation_id(operation_id)

    def get_type(self):
        return PORT_CONFIG

    def get_vm_id(self):
        return self.vm_id

    def set_vm_id(self, vm_id):
        vm_id = 0 if vm_id is None else vm_id
        try:
            self.vm_id = int(vm_id)
        except:
            self.vm_id = 0

    def get_vm_port(self):
        return self.vm_port

    def set_vm_port(self, vm_port):
        vm_port = 0 if vm_port is None else vm_port
        try:
            self.vm_port = int(vm_port)
        except:
            self.vm_port = 0

    def get_operation_id(self):
        return self.operation_id

    def set_operation_id(self, operation_id):
        operation_id = 0 if operation_id is None else operation_id
        try:
            self.operation_id = int(operation_id)
        except:
            self.operation_id = 0

    def from_dict(self, data):
        self.set_vm_id(data["vm_id"])
        self.set_vm_port(data["vm_port"])
        self.set_operation_id(data["operation_id"])

    def to_dict(self):
        data = {}
        data["vm_id"] = str(self.get_vm_id())
        data["vm_port"] = str(self.get_vm_port())
        data["operation_id"] = str(self.get_operation_id())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "PortConfig\n"
        s += "  vm_id: " + format_id(self.get_vm_id()) + "\n"
        s += "  vm_port: " + str(self.get_vm_port()) + "\n"
        s += "  operation_id: " + str(self.get_operation_id()) + "\n"
        return s


class DatapathPortRegister(MongoIPCMessage):
    def __init__(self, ct_id=None, dp_id=None, dp_port=None):
        self.set_ct_id(ct_id)
        self.set_dp_id(dp_id)
        self.set_dp_port(dp_port)

    def get_type(self):
        return DATAPATH_PORT_REGISTER

    def get_ct_id(self):
        return self.ct_id

    def set_ct_id(self, ct_id):
        ct_id = 0 if ct_id is None else ct_id
        try:
            self.ct_id = int(ct_id)
        except:
            self.ct_id = 0

    def get_dp_id(self):
        return self.dp_id

    def set_dp_id(self, dp_id):
        dp_id = 0 if dp_id is None else dp_id
        try:
            self.dp_id = int(dp_id)
        except:
            self.dp_id = 0

    def get_dp_port(self):
        return self.dp_port

    def set_dp_port(self, dp_port):
        dp_port = 0 if dp_port is None else dp_port
        try:
            self.dp_port = int(dp_port)
        except:
            self.dp_port = 0

    def from_dict(self, data):
        self.set_ct_id(data["ct_id"])
        self.set_dp_id(data["dp_id"])
        self.set_dp_port(data["dp_port"])

    def to_dict(self):
        data = {}
        data["ct_id"] = str(self.get_ct_id())
        data["dp_id"] = str(self.get_dp_id())
        data["dp_port"] = str(self.get_dp_port())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "DatapathPortRegister\n"
        s += "  ct_id: " + format_id(self.get_ct_id()) + "\n"
        s += "  dp_id: " + format_id(self.get_dp_id()) + "\n"
        s += "  dp_port: " + str(self.get_dp_port()) + "\n"
        return s


class DatapathDown(MongoIPCMessage):
    def __init__(self, ct_id=None, dp_id=None):
        self.set_ct_id(ct_id)
        self.set_dp_id(dp_id)

    def get_type(self):
        return DATAPATH_DOWN

    def get_ct_id(self):
        return self.ct_id

    def set_ct_id(self, ct_id):
        ct_id = 0 if ct_id is None else ct_id
        try:
            self.ct_id = int(ct_id)
        except:
            self.ct_id = 0

    def get_dp_id(self):
        return self.dp_id

    def set_dp_id(self, dp_id):
        dp_id = 0 if dp_id is None else dp_id
        try:
            self.dp_id = int(dp_id)
        except:
            self.dp_id = 0

    def from_dict(self, data):
        self.set_ct_id(data["ct_id"])
        self.set_dp_id(data["dp_id"])

    def to_dict(self):
        data = {}
        data["ct_id"] = str(self.get_ct_id())
        data["dp_id"] = str(self.get_dp_id())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "DatapathDown\n"
        s += "  ct_id: " + format_id(self.get_ct_id()) + "\n"
        s += "  dp_id: " + format_id(self.get_dp_id()) + "\n"
        return s


class VirtualPlaneMap(MongoIPCMessage):
    def __init__(self, vm_id=None, vm_port=None, vs_id=None, vs_port=None):
        self.set_vm_id(vm_id)
        self.set_vm_port(vm_port)
        self.set_vs_id(vs_id)
        self.set_vs_port(vs_port)

    def get_type(self):
        return VIRTUAL_PLANE_MAP

    def get_vm_id(self):
        return self.vm_id

    def set_vm_id(self, vm_id):
        vm_id = 0 if vm_id is None else vm_id
        try:
            self.vm_id = int(vm_id)
        except:
            self.vm_id = 0

    def get_vm_port(self):
        return self.vm_port

    def set_vm_port(self, vm_port):
        vm_port = 0 if vm_port is None else vm_port
        try:
            self.vm_port = int(vm_port)
        except:
            self.vm_port = 0

    def get_vs_id(self):
        return self.vs_id

    def set_vs_id(self, vs_id):
        vs_id = 0 if vs_id is None else vs_id
        try:
            self.vs_id = int(vs_id)
        except:
            self.vs_id = 0

    def get_vs_port(self):
        return self.vs_port

    def set_vs_port(self, vs_port):
        vs_port = 0 if vs_port is None else vs_port
        try:
            self.vs_port = int(vs_port)
        except:
            self.vs_port = 0

    def from_dict(self, data):
        self.set_vm_id(data["vm_id"])
        self.set_vm_port(data["vm_port"])
        self.set_vs_id(data["vs_id"])
        self.set_vs_port(data["vs_port"])

    def to_dict(self):
        data = {}
        data["vm_id"] = str(self.get_vm_id())
        data["vm_port"] = str(self.get_vm_port())
        data["vs_id"] = str(self.get_vs_id())
        data["vs_port"] = str(self.get_vs_port())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "VirtualPlaneMap\n"
        s += "  vm_id: " + format_id(self.get_vm_id()) + "\n"
        s += "  vm_port: " + str(self.get_vm_port()) + "\n"
        s += "  vs_id: " + format_id(self.get_vs_id()) + "\n"
        s += "  vs_port: " + str(self.get_vs_port()) + "\n"
        return s


class DataPlaneMap(MongoIPCMessage):
    def __init__(self, ct_id=None, dp_id=None, dp_port=None, vs_id=None, vs_port=None):
        self.set_ct_id(ct_id)
        self.set_dp_id(dp_id)
        self.set_dp_port(dp_port)
        self.set_vs_id(vs_id)
        self.set_vs_port(vs_port)

    def get_type(self):
        return DATA_PLANE_MAP

    def get_ct_id(self):
        return self.ct_id

    def set_ct_id(self, ct_id):
        ct_id = 0 if ct_id is None else ct_id
        try:
            self.ct_id = int(ct_id)
        except:
            self.ct_id = 0

    def get_dp_id(self):
        return self.dp_id

    def set_dp_id(self, dp_id):
        dp_id = 0 if dp_id is None else dp_id
        try:
            self.dp_id = int(dp_id)
        except:
            self.dp_id = 0

    def get_dp_port(self):
        return self.dp_port

    def set_dp_port(self, dp_port):
        dp_port = 0 if dp_port is None else dp_port
        try:
            self.dp_port = int(dp_port)
        except:
            self.dp_port = 0

    def get_vs_id(self):
        return self.vs_id

    def set_vs_id(self, vs_id):
        vs_id = 0 if vs_id is None else vs_id
        try:
            self.vs_id = int(vs_id)
        except:
            self.vs_id = 0

    def get_vs_port(self):
        return self.vs_port

    def set_vs_port(self, vs_port):
        vs_port = 0 if vs_port is None else vs_port
        try:
            self.vs_port = int(vs_port)
        except:
            self.vs_port = 0

    def from_dict(self, data):
        self.set_ct_id(data["ct_id"])
        self.set_dp_id(data["dp_id"])
        self.set_dp_port(data["dp_port"])
        self.set_vs_id(data["vs_id"])
        self.set_vs_port(data["vs_port"])

    def to_dict(self):
        data = {}
        data["ct_id"] = str(self.get_ct_id())
        data["dp_id"] = str(self.get_dp_id())
        data["dp_port"] = str(self.get_dp_port())
        data["vs_id"] = str(self.get_vs_id())
        data["vs_port"] = str(self.get_vs_port())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "DataPlaneMap\n"
        s += "  ct_id: " + format_id(self.get_ct_id()) + "\n"
        s += "  dp_id: " + format_id(self.get_dp_id()) + "\n"
        s += "  dp_port: " + str(self.get_dp_port()) + "\n"
        s += "  vs_id: " + format_id(self.get_vs_id()) + "\n"
        s += "  vs_port: " + str(self.get_vs_port()) + "\n"
        return s

class RouteMod(MongoIPCMessage):
    def __init__(self, mod=None, id=None, matches=None, 
                 actions=None, instructions=None, options=None):
        self.set_mod(mod)
        self.set_id(id)
        self.set_matches(matches)
        self.set_actions(actions)
        self.set_instructions(instructions)
        self.set_options(options)

    def get_type(self):
        return ROUTE_MOD

    def get_mod(self):
        return self.mod

    def set_mod(self, mod):
        mod = 0 if mod is None else mod
        try:
            self.mod = int(mod)
        except:
            self.mod = 0

    def get_id(self):
        return self.id

    def set_id(self, id):
        id = 0 if id is None else id
        try:
            self.id = int(id)
        except:
            self.id = 0

    def get_matches(self):
        return self.matches

    def set_matches(self, matches):
        matches = list() if matches is None else matches
        try:
            self.matches = list(matches)
        except:
            self.matches = list()

    def add_match(self, match):
        self.matches.append(match.to_dict())

    def get_actions(self):
        return self.actions

    def set_actions(self, actions):
        actions = list() if actions is None else actions
        try:
            self.actions = list(actions)
        except:
            self.actions = list()

    def add_action(self, action):
        self.actions.append(action.to_dict())

    def get_instructions(self):
        return self.instructions

    def set_instructions(self, instructions):
        instructions = list() if instructions is None else instructions
        try:
            self.instructions = list(instructions)
        except:
            self.instructions = list()

    def add_instructions(self, instruction):
        self.instructions.append(instruction.to_dict())

    def get_options(self):
        return self.options

    def set_options(self, options):
        options = list() if options is None else options
        try:
            self.options = list(options)
        except:
            self.options = list()

    def add_option(self, option):
        self.options.append(option.to_dict())

    def from_dict(self, data):
        self.set_mod(data["mod"])
        self.set_id(data["id"])
        self.set_matches(data["matches"])
        self.set_actions(data["actions"])
        self.set_instructions(data["instructions"])
        self.set_options(data["options"])

    def to_dict(self):
        data = {}
        data["mod"] = str(self.get_mod())
        data["id"] = str(self.get_id())
        data["matches"] = self.get_matches()
        data["actions"] = self.get_actions()
        data["instructions"] = self.get_instructions()
        data["options"] = self.get_options()
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "RouteMod\n"
        s += "  mod: " + str(self.get_mod()) + "\n"
        s += "  id: " + format_id(self.get_id()) + "\n"
        s += "  matches:\n"
        for match in self.get_matches():
            s += "    " + str(Match.from_dict(match)) + "\n"
        s += "  actions:\n"
        for action in self.get_actions():
            s += "    " + str(Action.from_dict(action)) + "\n"
        s += "  instructions:\n"
        for instruction in self.get_instructions():
            s += "    " + str(Instruction.from_dict(instruction)) + "\n"
        s += "  options:\n"
        for option in self.get_options():
            s += "    " + str(Option.from_dict(option)) + "\n"
        return s


class MeterMod(MongoIPCMessage):
    _FLAGS_KBPS = 1
    _FLAGS_PKTPS = 2
    _FLAGS_BURST = 4
    _FLAGS_STATS = 8

    _COMMAND_ADD = 0
    _COMMAND_MODIFY = 1
    _COMMAND_DELETE = 2
    
    def __init__(self, id=None, meter_id=None, meter_command=None, meter_flags=None, meter_bands=None):
        self.set_id(id)
        self.set_meter_id(meter_id)
        self.set_meter_command(meter_command)
        self.set_meter_flags(meter_flags)
        self.set_meter_bands(meter_bands)      

    def get_type(self):
        return METER_MOD

    def get_id(self):
        return self.id

    def set_id(self, id):
        id = 0 if id is None else id
        try:
            self.id = int(id)
        except:
            self.id = 0

    def get_meter_command(self):
        return self.meter_command

    def set_meter_command(self, meter_command):
        meter_command = 0 if meter_command is None else meter_command
        try:
            self.meter_command = int(meter_command)
        except:
            self.meter_command = 0

    def get_meter_id(self):
        return self.meter_id

    def set_meter_id(self, meter_id):
        meter_id = 0 if meter_id is None else meter_id
        try:
            self.meter_id = int(meter_id)
        except:
            self.meter_id = 0

    def get_meter_flags(self):
        return self.meter_flags

    def set_meter_flags(self, meter_flags):
        meter_flags = 0 if meter_flags is None else meter_flags
        try:
            self.meter_flags = int(meter_flags)
        except:
            self.meter_flags = 0

    def get_meter_bands(self):
        return self.meter_bands

    def set_meter_bands(self, meter_bands):
        meter_bands = dict() if meter_bands is None else meter_bands
        try:
            self.meter_bands = dict(meter_bands)
        except:
            self.meter_bands = dict()

    def add_meter_band(self, meter_band_type):
        self.meter_bands[meter_band_type] = []

    def add_meter_bands(self, meter_band_type, meter_band_attrib):
        if str(meter_band_type) in self.meter_bands.keys():
            self.meter_bands[str(meter_band_type)].append(meter_band_attrib.to_dict())
        else:
            self.add_meter_band(str(meter_band_type))
            self.meter_bands[str(meter_band_type)].append(meter_band_attrib.to_dict())

    def from_dict(self, data):
        self.set_meter_id(data["meter_id"])
        self.set_meter_command(data["meter_command"])
        self.set_meter_bands(data["meter_bands"])

    def to_dict(self):
        data = {}
        data["meter_id"] = str(self.get_meter_id())
        data["meter_command"] = str(self.get_meter_command())
        data["meter_bands"] = self.get_meter_bands()
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "MeterMod\n"
        s += "  meter_id: " + str(self.get_meter_id()) + "\n"
        s += "  meter_command: " + str(self.get_meter_command()) + "\n"
        s += "  meter_bands:\n"
        meter_bands = self.get_meter_bands()
        for meter_band in meter_bands.keys():
            for meter_band_attrib in meter_bands[meter_band]: 
                s += "    " + str(Meter.from_dict(meter_band_attrib)) + "\n"
        return s


class GroupMod(MongoIPCMessage):
    _TYPE_ALL = 1
    _TYPE_SELECT = 2
    _TYPE_INDIRECT = 3
    _TYPE_FF = 4

    def __init__(self, group_id=None, group_command=None, group_type=None,
                 group_actions=None, group_buckets=None):
        self.group_bucket_actions_id = 1
        self.group_bucket_id = 1
        self.set_group_id(group_id)
        self.set_group_command(group_command)
        self.set_group_type(group_type)
        self.set_group_actions(group_actions)
        self.set_group_buckets(group_buckets)      

    def get_type(self):
        return GROUP_MOD

    def get_group_id(self):
        return self.group_id

    def set_group_id(self, group_id):
        group_id = 0 if group_id is None else group_id
        try:
            self.group_id = int(group_id)
        except:
            self.group_id = 0

    def get_group_command(self):
        return self.group_command

    def set_group_command(self, group_command):
        group_command = 0 if group_command is None else group_command
        try:
            self.group_command = int(group_command)
        except:
            self.group_command = 0

    def get_group_type(self):
        return self.group_type

    def set_group_type(self, group_type):
        group_type = 0 if group_type is None else group_type
        try:
            self.group_type = int(group_type)
        except:
            self.group_type = 0

    def get_group_actions(self):
        return self.group_actions

    def set_group_actions(self, group_actions):
        group_actions = dict() if group_actions is None else group_actions
        try:
            self.group_actions = dict(group_actions)
        except:
            self.group_actions = dict()

    def add_group_bucket_action(self, group_bucket_actions_id):
        self.group_actions[group_bucket_actions_id] = []
    
    def add_group_bucket_action_attribs(self, group_bucket_actions_id, group_action_attrib):
        if group_bucket_actions_id not in self.group_actions.keys():
            self.add_group_bucket_action(group_bucket_actions_id)
        if group_bucket_actions_id in self.group_actions.keys(): 
            self.group_actions[group_bucket_actions_id].append(group_action_attrib.to_dict())

    def get_group_buckets(self):
        return self.group_buckets

    def set_group_buckets(self, group_buckets):
        group_buckets = dict() if group_buckets is None else group_buckets
        try:
            self.group_buckets = dict(group_buckets)
        except:
            self.group_buckets = dict()

    def add_group_bucket(self):
        self.group_bucket_id += 1
        self.group_buckets[self.group_bucket_id] = []
        return self.group_bucket_id

    def add_group_bucket_attribs(self, group_bucket_id, group_bucket_attribs):
        if group_bucket_id in self.group_buckets.keys(): 
            self.group_buckets[group_bucket_id].append(group_bucket_attribs.to_dict())

    def from_dict(self, data):
        self.set_group_id(data["group_id"])
        self.set_group_command(data["group_command"])
        self.set_group_actions(data["group_actions"])
        self.set_group_buckets(data["group_buckets"])

    def to_dict(self):
        data = {}
        data["group_id"] = str(self.get_group_id())
        data["group_command"] = str(self.get_group_command())
        data["group_actions"] = self.get_group_actions()
        data["group_buckets"] = self.get_group_buckets()
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "RouteMod\n"
        s += "  group_id: " + str(self.get_group_id()) + "\n"
        s += "  group_command: " + str(self.get_group_command()) + "\n"
        s += "  group_actions:\n"
        for group_action in self.get_group_actions():
            s += "    " + str(Action.from_dict(group_action)) + "\n"
        s += "  group_buckets:\n"
        group_buckets = self.get_group_buckets()
        for group_bucket_type in group_buckets.keys():
            for group_bucket_attrib in group_buckets[group_bucket_type]:
                s += "    " + str(Group.from_dict(group_bucket_attrib)) + "\n"
        return s


class ControllerRegister(MongoIPCMessage):
    def __init__(self, ct_addr=None, ct_port=None, ct_role=None):
        self.set_ct_addr(ct_addr)
        self.set_ct_port(ct_port)
        self.set_ct_role(ct_role)

    def get_type(self):
        return CONTROLLER_REGISTER

    def get_ct_addr(self):
        return self.ct_addr

    def set_ct_addr(self, ct_addr):
        ct_addr = "" if ct_addr is None else ct_addr
        try:
            self.ct_addr = str(ct_addr)
        except:
            self.ct_addr = ""

    def get_ct_port(self):
        return self.ct_port

    def set_ct_port(self, ct_port):
        ct_port = 0 if ct_port is None else ct_port
        try:
            self.ct_port = int(ct_port)
        except:
            self.ct_port = 0

    def get_ct_role(self):
        return self.ct_role

    def set_ct_role(self, ct_role):
        ct_role = "" if ct_role is None else ct_role
        try:
            self.ct_role = str(ct_role)
        except:
            self.ct_role = ""

    def from_dict(self, data):
        self.set_ct_addr(data["ct_addr"])
        self.set_ct_port(data["ct_port"])
        self.set_ct_role(data["ct_role"])

    def to_dict(self):
        data = {}
        data["ct_addr"] = str(self.get_ct_addr())
        data["ct_port"] = str(self.get_ct_port())
        data["ct_role"] = self.get_ct_role()
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "ControllerRegister\n"
        s += "  ct_addr: " + str(self.get_ct_addr()) + "\n"
        s += "  ct_port: " + str(self.get_ct_port()) + "\n"
        s += "  ct_role: " + str(self.get_ct_role()) + "\n"
        return s


class ElectMaster(MongoIPCMessage):
    def __init__(self, ct_addr=None, ct_port=None):
        self.set_ct_addr(ct_addr)
        self.set_ct_port(ct_port)

    def get_type(self):
        return ELECT_MASTER

    def get_ct_addr(self):
        return self.ct_addr

    def set_ct_addr(self, ct_addr):
        ct_addr = "" if ct_addr is None else ct_addr
        try:
            self.ct_addr = str(ct_addr)
        except:
            self.ct_addr = ""

    def get_ct_port(self):
        return self.ct_port

    def set_ct_port(self, ct_port):
        ct_port = 0 if ct_port is None else ct_port
        try:
            self.ct_port = int(ct_port)
        except:
            self.ct_port = 0

    def from_dict(self, data):
        self.set_ct_addr(data["ct_addr"])
        self.set_ct_port(data["ct_port"])

    def to_dict(self):
        data = {}
        data["ct_addr"] = str(self.get_ct_addr())
        data["ct_port"] = str(self.get_ct_port())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "ElectMaster\n"
        s += "  ct_addr: " + str(self.get_ct_addr()) + "\n"
        s += "  ct_port: " + str(self.get_ct_port()) + "\n"
        return s


class DataPlaneLink(MongoIPCMessage):
    def __init__(self, ct_id=None, dp_src_id=None, dp_src_port=None, dp_dst_id=None, dp_dst_port=None, is_removal=False):
        self.set_ct_id(ct_id)
        self.set_dp_src_id(dp_src_id)
        self.set_dp_src_port(dp_src_port)
        self.set_dp_dst_id(dp_dst_id)
        self.set_dp_dst_port(dp_dst_port)
        self.set_is_removal(is_removal)

    def get_type(self):
        return DATA_PLANE_LINK

    def get_ct_id(self):
        return self.ct_id

    def set_ct_id(self, ct_id):
        ct_id = 0 if ct_id is None else ct_id
        try:
            self.ct_id = int(ct_id)
        except:
            self.ct_id = 0

    def get_dp_src_id(self):
        return self.dp_src_id

    def set_dp_src_id(self, dp_id):
        dp_src_id = 0 if dp_id is None else dp_id
        try:
            self.dp_src_id = int(dp_src_id)
        except:
            self.dp_src_id = 0

    def get_dp_src_port(self):
        return self.dp_src_port

    def set_dp_src_port(self, dp_port):
        dp_src_port = 0 if dp_port is None else dp_port
        try:
            self.dp_src_port = int(dp_src_port)
        except:
            self.dp_src_port = 0

    def get_dp_dst_id(self):
        return self.dp_dst_id

    def set_dp_dst_id(self, dp_id):
        dp_dst_id = 0 if dp_id is None else dp_id
        try:
            self.dp_dst_id = int(dp_dst_id)
        except:
            self.dp_dst_id = 0

    def get_dp_dst_port(self):
        return self.dp_dst_port

    def set_dp_dst_port(self, dp_port):
        dp_dst_port = 0 if dp_port is None else dp_port
        try:
            self.dp_dst_port = int(dp_dst_port)
        except:
            self.dp_dst_port = 0

    def set_is_removal(self, is_removal):
        self.is_removal = is_removal

    def get_is_removal(self):
        return self.is_removal

    def from_dict(self, data):
        self.set_ct_id(data["ct_id"])
        self.set_dp_src_id(data["dp_src_id"])
        self.set_dp_src_port(data["dp_src_port"])
        self.set_dp_dst_id(data["dp_dst_id"])
        self.set_dp_dst_port(data["dp_dst_port"])
        self.set_is_removal(data["is_removal"])

    def to_dict(self):
        data = {}
        data["ct_id"] = str(self.get_ct_id())
        data["dp_src_id"] = str(self.get_dp_src_id())
        data["dp_src_port"] = str(self.get_dp_src_port())
        data["dp_dst_id"] = str(self.get_dp_dst_id())
        data["dp_dst_port"] = str(self.get_dp_dst_port())
        data["is_removal"] = bool(self.get_is_removal())
        return data

    def from_bson(self, data):
        data = bson.BSON.decode(data)
        self.from_dict(data)

    def to_bson(self):
        return bson.BSON.encode(self.get_dict())

    def __str__(self):
        s = "DataPlaneLink\n"
        s += "  ct_id: " + str(self.get_ct_id()) + "\n"
        s += "  dp_src_id: " + str(self.get_dp_src_id()) + "\n"
        s += "  dp_src_port: " + str(self.get_dp_src_port()) + "\n"
        s += "  dp_dst_id: " + str(self.get_dp_dst_id()) + "\n"
        s += "  dp_dst_port: " + str(self.get_dp_dst_port()) + "\n"
        s += "  is_removal: " + str(self.get_is_removal()) + "\n"
        return s
