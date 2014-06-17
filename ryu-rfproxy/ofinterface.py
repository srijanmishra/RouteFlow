import logging

from rflib.defs import *
from binascii import *
from rflib.types.TLV import *
from rflib.types.Match import *
from rflib.types.Action import *
from rflib.types.Instruction import *
from rflib.types.Meter import *
from rflib.types.Group import *
from rflib.types.Option import *

OFP_BUFFER_NONE = 0xffffffff
log = logging.getLogger('ryu.app.rfproxy')


def create_default_flow_mod(dp, cookie=0, cookie_mask=0, table_id=0,
                            command=None, idle_timeout=0, hard_timeout=0,
                            priority=PRIORITY_LOWEST,
                            buffer_id=0xffffffff, match=None, actions=None,
                            inst_type=None, out_port=None, out_group=None,
                            flags=0, inst=[]):

    parser = dp.ofproto_parser
    ofproto = dp.ofproto
    
    if command == RMT_ADD:
        command = ofproto.OFPFC_ADD
    elif command == RMT_DELETE:
        command = ofproto.OFPFC_DELETE_STRICT
    
    if inst is []:
        if inst_type is None:
            inst_type = ofproto.OFPIT_APPLY_ACTIONS

        if actions is not None:
            inst = [parser.OFPInstructionActions(inst_type,
                                                 actions)]

    if match is None:
        match = parser.OFPMatch()

    if out_port is None:
        out_port = ofproto.OFPP_ANY

    if out_group is None:
        out_group = ofproto.OFPG_ANY

    return parser.OFPFlowMod(dp, cookie, cookie_mask,
                            table_id, command,
                            idle_timeout, hard_timeout,
                            priority, buffer_id,
                            out_port, out_group,
                            flags, match, inst)


def create_default_group_mod(dp, group_id, group_command, group_type):
    weight = 1
    watch_port = 0
    watch_group = 0
    dst_port= 0
    buckets = []
    if group_command == 0:
        command = dp.ofproto.OFPGC_ADD
    elif group_command == 1:
        command = dp.ofproto.OFPGC_MODIFY
    elif group_command == 2:
        command = dp.ofproto.OFPGC_DELETE
    actions = [dp.ofproto_parser.OFPActionOutput(dst_port, dp.ofproto.OFPCML_NO_BUFFER)]
    buckets = [dp.ofproto_parser.OFPBucket(weight, watch_port, watch_group, actions)]
    msg = dp.ofproto_parser.OFPGroupMod(dp, command, group_type, group_id, buckets)
    return msg


def create_default_meter_mod(dp, meter_id, meter_command, meter_flags):
    if meter_command == 0:
        command = dp.ofproto.OFPMC_ADD
    elif meter_command == 1:
        command = dp.ofproto.OFPMC_MODIFY
    elif meter_command == 2:
        command = dp.ofproto.OFPMC_DELETE
    bands = [dp.ofproto_parser.OFPMeterBandDrop(0, 0)]
    meter_mod = dp.ofproto_parser.OFPMeterMod(dp, command, meter_flags, meter_id, bands)
    return meter_mod
        
        
def create_flow_mod(dp, mod_command, matches, instructions, actions, options):
    flow_mod = create_default_flow_mod(dp, command=mod_command)
    add_matches(flow_mod, matches)
    add_instructions(flow_mod, instructions, actions)
    add_options(flow_mod, options)
    return flow_mod


def create_meter_mod(dp, meter_id, meter_command, meter_flags, meter_bands):
    meter_mod = create_default_meter_mod(dp, meter_id, meter_command, meter_flags)
    add_meter_bands(meter_mod, meter_bands)
    return meter_mod
    

def create_group_mod(dp, group_id, group_command, group_type, group_actions, group_buckets):
    group_mod = create_default_group_mod(dp, group_id, group_command, group_type)
    add_group_buckets(group_mod, group_actions, group_buckets)
    return group_mod


def add_matches(flow_mod, matches):
    for m in matches:
        match = Match.from_dict(m)
        if match._type == RFMT_IPV4:
            value = bin_to_int(match._value)
            addr = value >> 32
            mask = value & ((1 << 32) - 1)
            flow_mod.match.set_dl_type(ETHERTYPE_IP)
            flow_mod.match.set_ipv4_dst_masked(addr, mask)
        elif match._type == RFMT_IPV6:
            v = match._value
            addr = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                         for i in range(0, 16, 2))
            mask = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                         for i in range(16, 32, 2))
            flow_mod.match.set_dl_type(ETHERTYPE_IPV6)
            flow_mod.match.set_ipv6_dst_masked(addr, mask)
        elif match._type == RFMT_ETHERNET:
            flow_mod.match.set_dl_dst(match._value)
        elif match._type == RFMT_ETHERTYPE:
            flow_mod.match.set_dl_type(bin_to_int(match._value))
        elif match._type == RFMT_NW_PROTO:
            flow_mod.match.set_ip_proto(bin_to_int(match._value))
        elif match._type == RFMT_TP_SRC:
            flow_mod.match.set_ip_proto(IPPROTO_TCP)
            flow_mod.match.set_tcp_src(bin_to_int(match._value))
        elif match._type == RFMT_TP_DST:
            flow_mod.match.set_ip_proto(IPPROTO_TCP)
            flow_mod.match.set_tcp_dst(bin_to_int(match._value))
        elif match._type == RFMT_IN_PORT:
            flow_mod.match.set_in_port(bin_to_int(match._value))
        elif TLV.optional(match):
            log.info("Dropping unsupported Match (type: %s)" % match._type)
        else:
            log.warning("Failed to serialise Match (type: %s)" % match._type)
            return


def add_actions(flow_mod, action_tlvs):
    parser = flow_mod.datapath.ofproto_parser
    ofproto = flow_mod.datapath.ofproto
    actions = []
    for a in action_tlvs:
        action = Action.from_dict(a)
        if action._type == RFAT_OUTPUT:
            port = bin_to_int(action._value)
            a = parser.OFPActionOutput(port, ofproto.OFPCML_MAX)
            actions.append(a)
        elif action._type == RFAT_SET_ETH_SRC:
            srcMac = action._value
            src = parser.OFPMatchField.make(ofproto.OXM_OF_ETH_SRC, srcMac)
            actions.append(parser.OFPActionSetField(src))
        elif action._type == RFAT_SET_ETH_DST:
            dstMac = action._value
            dst = parser.OFPMatchField.make(ofproto.OXM_OF_ETH_DST, dstMac)
            actions.append(parser.OFPActionSetField(dst))
        elif action._type == RFAT_GROUP:
            group_id = action._value
            actions.append(parser.OFPActionGroup(group_id))
        elif action._type == RFAT_PUSH_MPLS:
            label = bin_to_int(action._value)
            actions.append(parser.OFPActionPushMpls(ether.ETH_TYPE_MPLS) )
            field = parser.OFPMatchField.make(dp.ofproto.OXM_OF_MPLS_LABEL, label)
            actions.append(parser.OFPActionSetField(field))           
        elif action._type == RFAT_POP_MPLS:
            ethertype = bin_to_int(action._value)
            actions.append(dp.ofproto_parser.OFPActionPopMpls(ether.ETH_TYPE_IP))
        elif action.optional():
            log.info("Dropping unsupported Action (type: %s)" % action._type)
        else:
            log.warning("Failed to serialise Action (type: %s)" % action._type)
            return
    return actions


def add_instructions(flow_mod, instruction_tlvs, action_tlvs=[]):
    parser = flow_mod.datapath.ofproto_parser
    ofproto = flow_mod.datapath.ofproto
    actions = add_actions(flow_mod, action_tlvs)
    instructions = []
    for a in instruction_tlvs:
        instruction = Instruction.from_dict(a)
        if instruction._type == RFIT_METER:
            meter_id = bin_to_int(instruction._value)
            a = parser.OFPInstructionMeter(meter_id)
            instructions.append(a)
        elif instruction._type == RFIT_APPLY_ACTIONS:
            a = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            instructions.append(a)
        elif instruction._type == RFIT_WRITE_ACTIONS:
            a = parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)
            instructions.append(a)
        elif instruction._type == RFIT_CLEAR_ACTIONS:
            a = parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)
            instructions.append(a)
        elif instruction._type == RFIT_WRITE_METADATA:
            metadata,metadata_mask = bin_to_int(instruction._value)
            a = parser.OFPInstructionWriteMetadata(ofproto.OFPIT_CLEAR_ACTIONS, metadata, metadata_mask)
            instructions.append(a)
        elif instruction._type == RFIT_GO_TABLE:
            next_table_id = instruction._value
            a = parser.OFPInstructionGotoTable(next_table_id)
            instructions.append(a)
        elif instruction.optional():
            log.info("Dropping unsupported instruction (type: %s)" % instruction._type)
        else:
            log.warning("Failed to serialise instruction (type: %s)" % instruction._type)
            return
    flow_mod.instructions = instructions

def add_meter_bands(meter_mod, meter_bands_dict):
    parser = meter_mod.datapath.ofproto_parser
    ofproto = meter_mod.datapath.ofproto
    meter_bands = []
    
    for meter_band_type in meter_bands_dict.keys():
        meter_type = None
        meter_rate = None
        meter_burst = None
        meter_exp = None
        meter_prec_level = None 
        for attrib in meter_bands_dict[meter_band_type]:
            meter_band_attrib = Meter.from_dict(attrib)
            if meter_band_attrib._type == RFMT_TYPE:
                meter_type = bin_to_int(meter_band_attrib._value)
            if meter_band_attrib._type == RFMT_RATE:
                meter_rate = bin_to_int(meter_band_attrib._value)
            if meter_band_attrib._type == RFMT_BURST:
                meter_burst = bin_to_int(meter_band_attrib._value)
            if meter_band_attrib._type == RFMT_PREC_LEVEL:
                meter_prec_level = bin_to_int(meter_band_attrib._value)
            if meter_band_attrib._type == RFMT_EXP:
                meter_exp = bin_to_int(meter_band_attrib._value)
        if meter_band_type == str(Meter._TYPE_DROP):
            meter_bands.append( parser.OFPMeterBandDrop(meter_rate, meter_burst) )
        if meter_band_type == str(Meter._TYPE_DSCP_REMARK):
            meter_bands.append( parser.OFPMeterBandDscpRemark(meter_rate, meter_burst, meter_prec_level) )
        if meter_band_type == str(Meter._TYPE_EXPERIMENTER):
            meter_bands.append( parser.OFPMeterBandExperimenter(meter_rate, meter_burst, meter_exp) )
    meter_mod.bands = meter_bands


def add_group_buckets(group_mod, group_actions, group_buckets):
    parser = group_mod.datapath.ofproto_parser
    ofproto = group_mod.datapath.ofproto
    buckets = []
    for bucket_id in group_buckets.keys():
        for attrib in group_buckets[bucket_id]:
            bucket_attrib = Group.from_dict(attrib)
            if bucket_attrib._type == RFGP_WEIGHT:
                bucket_weight = bin_to_int(bucket_attrib._value)
            if bucket_attrib._type == RFGP_WATCH_PORT:
                bucket_watch_port = bin_to_int(bucket_attrib._value)
            if bucket_attrib._type == RFGP_WATCH_GROUP:
                bucket_watch_group = bin_to_int(bucket_attrib._value)
            if bucket_attrib._type == RFGP_ACTIONS:
                bucket_actions_id = bin_to_int(bucket_attrib._value)
                if str(bucket_actions_id) in group_actions.keys():
                    bucket_actions = add_actions(group_mod, group_actions[str(bucket_actions_id)])
        buckets.append( parser.OFPBucket(bucket_weight, bucket_watch_port,
                                         bucket_watch_group, bucket_actions) )

    group_mod.buckets = buckets


def add_options(flow_mod, options):
    for o in options:
        option = Option.from_dict(o)
        if option._type == RFOT_PRIORITY:
            flow_mod.priority = bin_to_int(option._value)
        elif option._type == RFOT_IDLE_TIMEOUT:
            flow_mod.idle_timeout = bin_to_int(option._value)
        elif option._type == RFOT_HARD_TIMEOUT:
            flow_mod.hard_timeout = bin_to_int(option._value)
        elif option._type == RFOT_TABLE:
            flow_mod.table_id = bin_to_int(option._value)
        elif option._type == RFOT_CT_ID:
            pass
        elif option.optional():
            log.info("Dropping unsupported Option (type: %s)" % option._type)
        else:
            log.warning("Failed to serialise Option (type: %s)" % option._type)
            return


def send_pkt_out(dp, port, msg_data):
    actions = []
    actions.append(dp.ofproto_parser.OFPActionOutput(port, len(msg_data)))
    buffer_id = OFP_BUFFER_NONE
    in_port = dp.ofproto.OFPP_ANY
    packet_out = dp.ofproto_parser.OFPPacketOut(dp, buffer_id, in_port,
                                                actions, msg_data)
    dp.send_msg(packet_out)


def parse_role_request(role_request, dp):
    """Returns controller role code for given role_request.
    default -- No change.

    Keyword arguments:
    role_request -- Role request string.
    dp -- datapath for the device.

    """
    ofp = dp.ofproto
    if role_request == "master":
        role = ofp.OFPCR_ROLE_MASTER
    elif role_request == "slave":
        role = ofp.OFPCR_ROLE_SLAVE
    elif role_request == "equal":
        role = ofp.OFPCR_ROLE_EQUAL
    else:
        role = ofp.OFPCR_ROLE_NOCHANGE
    return role


def send_role_request(role, dp):
    """Send controller role to the device.

    Keyword arguments:
    role -- controller role.
    dp -- datapath for the device.

    """
    ofp_parser = dp.ofproto_parser

    req = ofp_parser.OFPRoleRequest(dp, role, 0)
    dp.send_msg(req)
