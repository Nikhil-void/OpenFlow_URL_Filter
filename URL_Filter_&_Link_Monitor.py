# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4, udp, arp, icmp
from ryu.lib.packet import ether_types
from scapy.arch import get_if_hwaddr
import time
import chardet
import os
import json
from ryu.lib.packet import *
import scapy.all as scapy
import binascii

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        # Below variables are declared for maintaining network topology information
        self.mac_to_port = {}
        self.remove_map = [("30.30.30.3", 1, 'F'), ("30.30.30.2",11, 'B')] # Port of partcular OvS to remove when link failure occurs
        self.remove_ip = ["30.30.30.3", "30.30.30.2"] # Management IP's of OvS where link failure can occur
        self.counter = 0
        self.controller_ip = "192.168.1.14" # IP of RYU controller towards Internet
        self.topology_map = {
                 "30.30.30.3":{"F":[[0,1, True], [1,2, True]], "B":[(0,5)]},
                 "30.30.30.2":{"F":[[0,8]],              "B":[[0,11, True], [1,9, True]]},
                 "30.30.30.4":{"F":[[0,1]],             "B":[(0,2)]},
                 "30.30.30.1":{"F":[[0,17]],              "B":[(0,18)]},
                 "30.30.30.5":{"F":[[0,19]],             "B":[(0,18)]},
                } # Map of Network topology
        #self.host_data = ["90.90.90.2", "5c:26:0a:24:8d:7a"]
        self.server_hwadrr = "00:23:33:35:98:21" # MAC address of Default Gateway aka Cisco Router

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        #return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    # This function detects if there has been a port change in the network and asks the device for port description statistics
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_stat_changed(self,ev):
        dp = ev.msg.datapath
        ofp_parser = dp.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(dp, 0) # Asking device to send port description statistics
        time.sleep(3)
        dp.send_msg(req)

    # This function is called when a switch send port description statistics
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def handle_port_change(self, ev):
        server_ip = ev.msg.datapath.address
        # If the IP of the switch is not one of the switches where link failure can occur, we exit 
        if server_ip[0] not in self.remove_ip:
            return
        
        # Checking the status of the port where link failure can occur 
        check_port  = [val[1] for val in self.remove_map if val[0] == server_ip[0]][0]
        status = [i.state for i in ev.msg.body if i.port_no == check_port][0]
        print("### Port Status Change Found ###")

        # Below for loop modifies topology map based on the current Port description received
        # Higher priority port is set to True = Up if status = 4 received from switch else set to down and hence lower priority path will be taken
        for ip, port, direction in self.remove_map:
            for d, l in self.topology_map[ip].items():
                if not d == direction:
                    continue
                for val in l:
                    if not val[1] == port:
                        continue
                    val[2] = True if status == 4 else False
                    priority = "Higher" if val[2] == True else "Lower"
                print("Changing to %s priority path for switch with IP: %s" % (priority, ip))
        


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        direction = "B" if  eth.src == self.server_hwadrr else "F" # Packet direction determined by MAC address of Default Gateway
        #direction = "F" if  eth.dst != self.host_data[1] else "B"

        # Extracting information form packets
        ip = pkt.get_protocols(ipv4.ipv4)
        udp_pkt = pkt.get_protocols(udp.udp)
        current_switch = datapath.address[0]
        arp_pkt = pkt.get_protocols(arp.arp)
        mac_address = get_if_hwaddr("eno1")
        icmp_packet = pkt.get_protocols(icmp.icmp)
        dpid = format(datapath.id, "d").zfill(16)

        #Below if block is used to drop DHCP packets generated by any switch and print other DHCP request packets
        if len(udp_pkt) > 0 and udp_pkt[0].dst_port == 67: 
            if eth.src.startswith("14:18:77"):
                return
            print("## DHCP Request Packet found from source : %s  on Switch IP: %s ##" % (eth.src, current_switch))
        # Below if block is used to print and track reply DHCP packets
        if len(udp_pkt) > 0 and udp_pkt[0].dst_port == 68:
            print("## DHCP Reply Packet found for destination : %s on Switch IP: %s ##" % (eth.dst, current_switch))


        # Below code is to handle DNS packets
        if len(ip) > 0 and len(udp_pkt) > 0 and ip[0].proto == 17 and udp_pkt[0].dst_port == 53:
            domain = pkt.data[55: len(pkt.data) -4] # Getting domain name out from payload
            final_domain = ''
            # Converting bytes to string
            for g in range(0,len(domain)-1):  
                if domain[g]<32 or domain[g]>126:
                    final_domain += '.'
                else:
                    final_domain += chr(domain[g])
            # Connecting to Flask Site checker application and checking current domain's status via REST
            status = os.popen("curl -s  http://127.0.0.1:80/site_checker?%s" % final_domain).read() 
            status = json.loads(status)
            ip_src = ip[0].dst
            ip_dst = ip[0].src
            sport = 53
            dport = udp_pkt[0].src_port
            # If status is bad, crafting a DNS reply packet, with rdata as controllers IP address so that the client which recieves this reply
            # will connect to the controllers Flask web page and get displayed a "Blocked Page" warning message
            if status['status'] == "bad":
                print("## Bad Website Found:  %s ##" % final_domain)
                query_id = binascii.hexlify(pkt.data[42:44])
                query_id = int(query_id.decode(), 16)
                a = scapy.Ether(dst=eth.src,src=mac_address) \
                /scapy.IP(dst=ip_dst,src=ip_src)/scapy.UDP(sport=sport,dport=dport) \
                /scapy.DNS(opcode=0,id=query_id,qr=1,rd=1,ra=1,aa=0,tc=0,z=0,ad=0,cd=0,rcode=0,qdcount=1,ancount=1,nscount=1,arcount=0,qd=scapy.DNSQR(qname=final_domain),
an=scapy.DNSRR(rrname=final_domain,ttl=60,rdata=self.controller_ip),ns=scapy.DNSRR(rrname=final_domain,type=2,ttl=60,rdata="ns1."+final_domain),ar=None)
                a = bytes(a)
                actions = [parser.OFPActionOutput(port=5)]
                out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=a)
                datapath.send_msg(out)
                return # Dropping original DNS request packet



        our_out = 0
        our_port = self.topology_map[current_switch][direction] # Deciding the out_port based of topology map
        for ports in our_port:
            if len(ports) == 2:
                our_out = ports[1]
                break
            else:
                if ports[2]: # This line checks if the higher priority port is up. If not, loop will continue and lower priority out port will get selected
                    our_out = ports[1]
                    break

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #else:
        #    #out_port = ofproto.OFPP_FLOOD
        out_port = our_out

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                pass
                #self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        
        # We check if ICMP packets are being sent and print its details to simulate traceroute
        if len(icmp_packet) > 0:
            print("ICMP packet with Source: %s and Destination: %s found at Switch with DPID = %s, IP = %s, In-Port = %s, Out-Port = %s "\
                    % (ip[0].src, ip[0].dst, dpid, current_switch, in_port, out_port))
            #print(pkt)
        datapath.send_msg(out)
