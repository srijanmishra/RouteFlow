import struct
import threading
import logging

from ofinterface import *

import rflib.ipc.IPC as IPC
import rflib.ipc.MongoIPC as MongoIPC
from rflib.ipc.RFProtocol import *
from rflib.ipc.RFProtocolFactory import RFProtocolFactory
from rflib.defs import *

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import *
from ryu.topology import switches, event
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.lib import hub
from ryu.lib.mac import *
from ryu.lib.dpid import *
from ryu.lib.packet.ethernet import ethernet

log = logging.getLogger('ryu.app.rfproxy')


# Association table
class Table:
    def __init__(self):
        self.dp_to_vs = {}
        self.vs_to_dp = {}

    def update_dp_port(self, dp_id, dp_port, vs_id, vs_port):
                # If there was a mapping for this DP port, reset it
        if (dp_id, dp_port) in self.dp_to_vs:
            old_vs_port = self.dp_to_vs[(dp_id, dp_port)]
            del self.vs_to_dp[old_vs_port]
        self.dp_to_vs[(dp_id, dp_port)] = (vs_id, vs_port)
        self.vs_to_dp[(vs_id, vs_port)] = (dp_id, dp_port)

    def dp_port_to_vs_port(self, dp_id, dp_port):
        try:
            return self.dp_to_vs[(dp_id, dp_port)]
        except KeyError:
            return None

    def vs_port_to_dp_port(self, vs_id, vs_port):
        try:
            return self.vs_to_dp[(vs_id, vs_port)]
        except KeyError:
            return None

    def delete_dp(self, dp_id):
        for (id_, port) in self.dp_to_vs.keys():
            if id_ == dp_id:
                del self.dp_to_vs[(id_, port)]

        for key in self.vs_to_dp.keys():
            id_, port = self.vs_to_dp[key]
            if id_ == dp_id:
                del self.vs_to_dp[key]

    # We're not considering the case of this table becoming invalid when a
    # datapath goes down. When the datapath comes back, the server recreates
    # the association, forcing new map messages to be generated, overriding the
    # previous mapping.
    # If a packet comes and matches the invalid mapping, it can be redirected
    # to the wrong places. We have to fix this.


def hub_thread_wrapper(target, args=()):
    result = hub.spawn(target, *args)
    result.start = lambda: target
    return result

# IPC message Processing
class RFProcessor(IPC.IPCMessageProcessor):

    def __init__(self, switches, table):
        self._switches = switches
        self.table = table

    def process(self, from_, to, channel, msg):
        type_ = msg.get_type()
        if type_ == ROUTE_MOD:
            switch = self._switches._get_switch(msg.get_id())
            dp = switch.dp
            ofmsg = create_flow_mod(dp, msg.get_mod(),
                                    msg.get_matches(),msg.get_instructions(), 
                                    msg.get_actions(), msg.get_options())
            try:
                dp.send_msg(ofmsg)
            except Exception as e:
                log.info("INFO:rfproxy:Error sending RouteMod:")
                log.info(type(e))
                log.info(str(e))
            else:
                log.info("INFO:rfproxy:ofp_flow_mod was sent to datapath (dp_id = %s)",
                         msg.get_id())
        elif type_ == METER_MOD:
            switch = self._switches._get_switch(msg.get_id())
            dp = switch.dp
            ofmsg = create_meter_mod(dp, msg.get_meter_id(),
                                     msg.get_meter_command(),msg.get_meter_flags(), 
                                     msg.get_meter_bands())
            try:
                dp.send_msg(ofmsg)
            except Exception as e:
                log.info("INFO:rfproxy:Error sending MeterMod:")
                log.info(type(e))
                log.info(str(e))
            else:
                log.info("INFO:rfproxy:ofp_meter_mod was sent to datapath (dp_id = %s)",
                         msg.get_id())
        elif type_ == GROUP_MOD:
            switch = self._switches._get_switch(msg.get_id())
            dp = switch.dp
            ofmsg = create_group_mod(dp, msg.get_group_id(), msg.get_group_command(),
                                     msg.get_group_type(),msg.get_group_actions(), 
                                     msg.get_group_buckets())
            try:
                dp.send_msg(ofmsg)
            except Exception as e:
                log.info("INFO:rfproxy:Error sending GroupMod:")
                log.info(type(e))
                log.info(str(e))
            else:
                log.info("INFO:rfproxy:ofp_group_mod was sent to datapath (dp_id = %s)",
                         msg.get_id())                                
        elif type_ == DATA_PLANE_MAP:
            dp_id = msg.get_dp_id()
            dp_port = msg.get_dp_port()
            vs_id = msg.get_vs_id()
            vs_port = msg.get_vs_port()

            self.table.update_dp_port(dp_id, dp_port, vs_id, vs_port)
            log.info("INFO:rfproxy:Updating vs-dp association (vs_id=%s, vs_port=%i, "
                     "dp_id=%s, dp_port=%i" % (dpid_to_str(vs_id), vs_port,
                                               dpid_to_str(dp_id), dp_port))
        elif type_ == ELECT_MASTER:
            host = msg.get_ct_addr()
            port = msg.get_ct_port()
            if (CONF.ofp_listen_host == host and
                CONF.ofp_tcp_listen_port == port):
                CONF.ofp_role = 'master'
                switches = self._switches._get_switches()
                for switch in switches:
                    dp = switch.dp
                    ofp_role = parse_role_request('master', dp)
                    send_role_request(ofp_role, dp)
        else:
            return False
        return True


class RFProxy(app_manager.RyuApp):
    #Listen to the Ryu topology change events
    _CONTEXTS = {'switches': switches.Switches}
    OFP_VERSIONS = [ofproto.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RFProxy, self).__init__(*args, **kwargs)

        self.ID = 0
        self.table = Table()
        self.switches = kwargs['switches']
        self.rfprocess = RFProcessor(self.switches, self.table)
        
        self.ipc = MongoIPC.MongoIPCMessageService(MONGO_ADDRESS,
                                                   MONGO_DB_NAME, str(self.ID),
                                                   hub_thread_wrapper,
                                                   hub.sleep)

        self.ipc.listen(RFSERVER_RFPROXY_CHANNEL, RFProtocolFactory(),
                        self.rfprocess, False)
        log.info("RFProxy running.")

    #Event handlers
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def handler_datapath_enter(self, ev):
        dp = ev.switch.dp
        ports = ev.switch.ports
        dpid = dp.id
        log.debug("INFO:rfproxy:Datapath is up (dp_id=%d)", dpid)
        for port in ports:
            if port.port_no <= dp.ofproto.OFPP_MAX:
                msg = DatapathPortRegister(ct_id=self.ID, dp_id=dpid,
                                           dp_port=port.port_no)
                self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
                log.info("INFO:rfproxy:Registering datapath port (dp_id=%s, dp_port=%d)",
                         dpid_to_str(dpid), port.port_no)




    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def handler_datapath_leave(self, ev):
        dp = ev.switch.dp
        dpid = dp.id
        log.info("INFO:rfproxy:Datapath is down (dp_id=%d)", dpid)
        self.table.delete_dp(dpid)
        msg = DatapathDown(ct_id=self.ID, dp_id=dpid)
        self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        src_dpid = src.dpid
        src_port = src.port_no
        dst_dpid = dst.dpid
        dst_port = dst.port_no
        log.info('INFO:rfproxy:Link add src.dpid %s src.port %d - dst.dpid %s dst.port %s', src_dpid, src_port, dst_dpid, dst_port)
        msg =  DataPlaneLink(ct_id=self.ID, dp_src_id=src_dpid, dp_src_port=src_port, dp_dst_id=dst_dpid, dp_dst_port=dst_port, is_removal=False)
        self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)


    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_del_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        src_dpid = src.dpid
        src_port = src.port_no
        dst_dpid = dst.dpid
        dst_port = dst.port_no
        log.info('INFO:rfproxy:Link del src.dpid %s src.port %d - dst.dpid %s dst.port %s', src_dpid, src_port, dst_dpid, dst_port)
        msg =  DataPlaneLink(ct_id=self.ID, dp_src_id=src_dpid, dp_src_port=src_port, dp_dst_id=dst_dpid, dp_dst_port=dst_port, is_removal=True)
        self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        pkt, ethertype, buff = ethernet.parser(msg.data)
        in_port = msg.match['in_port']

        # If we have a mapping packet, inform RFServer through a Map message
        if pkt.ethertype == RF_ETH_PROTO:
            vm_id, vm_port = struct.unpack("QB", msg.data[14:23])
            log.info("INFO:rfproxy:Received mapping packet (vm_id=%s, vm_port=%d, "
                     "vs_id=%s, vs_port=%d)", format_id(vm_id), vm_port,
                     dpid_to_str(dpid), in_port)
            msg = VirtualPlaneMap(vm_id=vm_id, vm_port=vm_port, vs_id=dpid,
                                  vs_port=in_port)
            self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
            return

        # If the packet came from RFVS, redirect it to the right switch port
        if is_rfvs(dpid):
            dp_port = self.table.vs_port_to_dp_port(dpid, in_port)
            if dp_port is not None:
                dp_id, dp_port = dp_port
                switch = self.switches._get_switch(dp_id)
                if switch is not None:
                    send_pkt_out(switch.dp, dp_port, msg.data)
                    log.debug("INFO:rfproxy:forwarding packet from rfvs (dp_id: %s, "
                             "dp_port: %d)", dpid_to_str(dp_id), dp_port)
                else:
                    log.warn("INFO:rfproxy:dropped packet from rfvs (dp_id: %s, "
                             "dp_port: %d)", dpid_to_str(dp_id), dp_port)
            else:
                log.debug("INFO:rfproxy:Unmapped RFVS port (vs_id=%s, vs_port=%d)",
                         dpid_to_str(dpid), in_port)
        # If the packet came from a switch, redirect it to the right RFVS port
        else:
            vs_port = self.table.dp_port_to_vs_port(dpid, in_port)
            if vs_port is not None:
                vs_id, vs_port = vs_port
                switch = self.switches._get_switch(vs_id)
                if switch is not None:
                    send_pkt_out(switch.dp, vs_port, msg.data)
                    log.debug("INFO:rfproxy:forwarding packet to rfvs (vs_id: %s, "
                              "vs_port: %d)", dpid_to_str(vs_id), vs_port)
                else:
                    log.warn("INFO:rfproxy:dropped packet to rfvs (vs_id: %s, "
                             "vs_port: %d)", dpid_to_str(dp_id), dp_port)
            else:
                log.debug("Unmapped datapath port (dp_id=%s, dp_port=%d)",
                         dpid_to_str(dpid), in_port)


    @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
    def role_reply_handler(self, ev):
        log.info('INFO:rfproxy:OFPRoleReply received')


    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        log.debug('INFO:rfproxy:OFPErrorMsg received: type=0x%02x code=0x%02x ''message=%s',
                 msg.type, msg.code, hex_array(msg.data))