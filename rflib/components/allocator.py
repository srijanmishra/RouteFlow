class Allocator(object):

    def __init__(self, ipc):
        #Define IPC from rfserver to send msgs to rfproxy
        self.ipc = ipc

    #TODO: Build functions above to be used in rfserver 
    #def send_datapath_routemod_msg(self, ct_id, dp_id):
        

    def send_datapath_config_message(self, ct_id, dp_id, operation_id):
        rm = RouteMod(RMC_ADD, dp_id)
        rm.set_instructions(None)
        rm.add_instructions(Instruction.APPLY_ACTIONS())
        if operation_id == DC_CLEAR_FLOW_TABLE:
            rm.set_mod(RMC_DELETE)
            rm.add_option(Option.PRIORITY(PRIORITY_LOWEST))
        elif operation_id == DC_DROP_ALL:
            rm.add_option(Option.PRIORITY(PRIORITY_LOWEST + PRIORITY_BAND))
            # No action specifies discard
            pass
        else:
            rm.add_option(Option.PRIORITY(PRIORITY_HIGH))
            if operation_id == DC_RIPV2:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_UDP))
                rm.add_match(Match.IPV4(IPADDR_RIPv2, IPV4_MASK_EXACT))
            elif operation_id == DC_OSPF:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_OSPF))
            elif operation_id == DC_ARP:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_ARP))
            elif operation_id == DC_ICMP:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_ICMP))
            elif operation_id == DC_ICMPV6:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IPV6))
                rm.add_match(Match.NW_PROTO(IPPROTO_ICMPV6))
            elif operation_id == DC_BGP_PASSIVE:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_TCP))
                rm.add_match(Match.TP_DST(TPORT_BGP))
            elif operation_id == DC_BGP_ACTIVE:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_TCP))
                rm.add_match(Match.TP_SRC(TPORT_BGP))
            elif operation_id == DC_LDP_PASSIVE:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_TCP))
                rm.add_match(Match.TP_DST(TPORT_LDP))
            elif operation_id == DC_LDP_ACTIVE:
                rm.add_match(Match.ETHERTYPE(ETHERTYPE_IP))
                rm.add_match(Match.NW_PROTO(IPPROTO_TCP))
                rm.add_match(Match.TP_SRC(TPORT_LDP))
            elif operation_id == DC_VM_INFO:
                rm.add_match(Match.ETHERTYPE(RF_ETH_PROTO))
            rm.add_action(Action.CONTROLLER())
        rm.add_option(Option.CT_ID(ct_id))
        self.ipc.send(RFSERVER_RFPROXY_CHANNEL, str(ct_id), rm)

        
    def configure_reset_topo(self, topoPhysical):
        dps = topoPhysical.get_dps()
        ct_id = topoPhysical.get_ct_id()
        for dp_id in dps.keys():
            self.send_datapath_config_message(ct_id, dp_id, DC_CLEAR_FLOW_TABLE)
            self.send_datapath_config_message(ct_id, dp_id, DC_OSPF)
            self.send_datapath_config_message(ct_id, dp_id, DC_BGP_PASSIVE)
            self.send_datapath_config_message(ct_id, dp_id, DC_BGP_ACTIVE)
            self.send_datapath_config_message(ct_id, dp_id, DC_RIPV2)
            self.send_datapath_config_message(ct_id, dp_id, DC_ARP)
            self.send_datapath_config_message(ct_id, dp_id, DC_ICMP)
            self.send_datapath_config_message(ct_id, dp_id, DC_LDP_PASSIVE)
            self.send_datapath_config_message(ct_id, dp_id, DC_LDP_ACTIVE)
        log.info("Reset physical topology finished")
    
