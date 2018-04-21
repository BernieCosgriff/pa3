from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ether_types

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    h5 = True

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        protocol = datapath.ofproto
        proto_parser = datapath.ofproto_parser

        match = proto_parser.OFPMatch()
        actions = [proto_parser.OFPActionOutput(protocol.OFPP_CONTROLLER,
                                          protocol.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        protocol = datapath.ofproto
        proto_parser = datapath.ofproto_parser
        instr = [proto_parser.OFPInstructionActions(protocol.OFPIT_APPLY_ACTIONS, actions)]
        flow = proto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=instr)
        datapath.send_msg(flow)

    def rcv_arp(self, datapath, pkt, eth, in_port ):
        arppkt = pkt.get_protocol(arp.arp)

        if arppkt.opcode == 1:
            if arppkt.dst_ip == "10.0.0.10":
                mac = ""
                ip = ""
                out_port = 0
                if self.h5:
                    mac = "00:00:00:00:00:05"
                    out_port = 5
                    ip = "10.0.0.5"
                    self.h5 = False
                else:
                    mac = "00:00:00:00:00:06"
                    out_port = 6
                    ip = "10.0.0.6"
                    self.h5 = True
                protocol = datapath.ofproto
                proto_parser = datapath.ofproto_parser

                match1 = proto_parser.OFPMatch(in_port=in_port, eth_dst=mac, eth_type=0x800)
                action1 = [proto_parser.OFPActionSetField(ipv4_dst=ip),
                         proto_parser.OFPActionOutput(out_port)]
                self.add_flow(
                    datapath=datapath,
                    priority=1,
                    match=match1,
                    actions=action1,
                )

                match2 = proto_parser.OFPMatch(in_port=out_port, eth_dst=arppkt.src_mac, eth_type=0x800)
                action2 = [proto_parser.OFPActionSetField(ipv4_src='10.0.0.10'),
                           proto_parser.OFPActionOutput(in_port)]
                self.add_flow(
                    datapath=datapath,
                    priority=1,
                    match=match2,
                    actions=action2,
                )

                arp_resp = self.create_arp(mac, "10.0.0.10", arppkt.src_mac, arppkt.src_ip)
                actions = [proto_parser.OFPActionOutput(in_port)]
                req = proto_parser.OFPPacketOut(
                    datapath=datapath,
                    in_port=protocol.OFPP_CONTROLLER,
                    actions=actions,
                    data=arp_resp,
                    buffer_id = protocol.OFP_NO_BUFFER
                )
                datapath.send_msg(req)

                arp_resp = self.create_arp(arppkt.src_mac, arppkt.src_ip, mac, ip)
                actions = [proto_parser.OFPActionOutput(out_port)]
                req = proto_parser.OFPPacketOut(
                    datapath=datapath,
                    in_port=protocol.OFPP_CONTROLLER,
                    actions=actions,
                    data=arp_resp,
                    buffer_id=protocol.OFP_NO_BUFFER
                )
                datapath.send_msg(req)

    def create_arp(self, src_mac, src_ip, dst_mac, dst_ip):
        eth = ethernet.ethernet(dst_mac, src_mac, ether_types.ETH_TYPE_ARP)
        resp = arp.arp_ip(2, src_mac, src_ip , dst_mac, dst_ip) #arp response opcode = 2

        print "Built ARP response->SrcMAC:", resp.src_mac, " SrcIP:", resp.src_ip, " DstMAC:", resp.dst_mac, " DstIP:", resp.dst_ip

        p = packet.Packet()
        p.add_protocol(eth)
        p.add_protocol(resp)
        p.serialize()

        return p

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.rcv_arp(datapath, pkt, eth, in_port)
