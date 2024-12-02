#!/usr/bin/env python3
import os
import time
import sys
import csv
import json
sys.path.append("utils")
import switch
sys.path.append("../../utils")
from p4runtime_lib import helper
from p4runtime_lib import convert
from p4.v1 import p4runtime_pb2
from scapy.all import IP, UDP,TCP, Ether, get_if_hwaddr, sendp
from scapy.all import (
    Packet,
    IP,
    sniff,
    MACField,
    TimeStampField,
    BitField,
    IPField,
    bind_layers,
)
from scapy.layers.inet import _IPOption_HDR

class Counter:
    def __init__(self):
        self.cnt=0
        self.timeTotal=0

class FadInfo(Packet):
    name = "FadInfo"
    fields_desc = [
        MACField("anomaly_switch_mac_addr",None),
        IPField("packet_dst_ip_addr",None),
    ]


def topo_loader():
    deviceMap = {}
    for i in range(1,17):
        dstMac = "ff:ff:ff:ff:ff:" + "{:02d}".format(i)
        deviceMap[dstMac] = i

    with open("topo/topology.json",'r') as f:
        content = json.load(f)
        portMap = {}
        for link in content["links"]:
            if link[0][0]=='h' or link[1][0]=='h':
                continue
            srcSwitch = int(link[0].split('-')[0][1:])
            srcPort = int(link[0].split('-')[1][1:])
            dstSwitch = int(link[1].split('-')[0][1:])
            dstPort = int(link[1].split('-')[1][1:])
            if srcSwitch not in portMap:
                portMap[srcSwitch]={}
            if dstSwitch not in portMap:
                portMap[dstSwitch]={}
            portMap[srcSwitch][srcPort] = dstSwitch
            portMap[dstSwitch][dstPort] = srcSwitch
        return portMap, deviceMap

def ip_encode(ipAddr):
    ip_address_segments = ipAddr.split(".")
    ip_address = 0
    for segment in ip_address_segments:
        ip_address = ip_address * 256 + int(segment)
    return ip_address

def ip_decode(ip):
    seg4 = str(ip%256)
    ip = int(ip/256)
    seg3 = str(ip%256)
    ip = int(ip/256)
    seg2 = str(ip%256)
    ip = int(ip/256)
    seg1 = str(ip%256)
    return ".".join([seg1,seg2,seg3,seg4])

def ip_mask(ip, suffix):
    zero_bit_length = 32-suffix
    ip>>zero_bit_length
    ip<<zero_bit_length
    return ip

def get_match_entry(switchConnection, ipAddr):
    p4info_helper = helper.P4InfoHelper("build/basic.p4.p4info.txt")
    table_name = "MyIngress.ipv4_lpm"
    match_field_name = "hdr.ipv4.dstAddr"
    table_id = p4info_helper.get_id("tables",table_name)
    p4info_match = p4info_helper.get_match_field(table_name, match_field_name)
    bitwidth = p4info_match.bitwidth
    

    li = []
    ip = ip_encode(ipAddr)
    for i in range(32,0,-1):
        table_entry = p4runtime_pb2.TableEntry()
        table_entry.table_id = table_id
        p4runtime_match = p4runtime_pb2.FieldMatch()
        p4runtime_match.field_id = p4info_match.id
        lpm_entry = p4runtime_match.lpm
        lpm_entry.value = convert.encode(ip_decode(ip), bitwidth)
        lpm_entry.prefix_len = i
        ip &= ~(1<<(32-i))
        table_entry.match.extend([p4runtime_match])
        response = next(switchConnection.ReadTableEntry(table_entry)).entities
        if(len(response)!=0):
            return response[0].table_entry

def switch_connection_loader():
    connectionMap = {}
    electionSeriesNumber = 43
    for injectionSwitchId in range(1,17):
        hostRpcServerAddr = "127.0.0.1:" + str(50050+injectionSwitchId)
        tableEntryWriteLogFile = "entryLogs/s{}-p4runtime-requests.txt".format(injectionSwitchId)
        connectionMap[injectionSwitchId] = switch.SwitchConnection(str(injectionSwitchId)+"Connection",
                                                    address=hostRpcServerAddr, 
                                                    device_id=injectionSwitchId-1,
                                                    proto_dump_file=tableEntryWriteLogFile)
    return connectionMap

def handle_pkt(pkt,portMap, deviceMap,connectionMap,counter):
    if FadInfo in pkt:
        counter.cnt+=1
        times = -time.time_ns()
        anomalySwitch = deviceMap[pkt.anomaly_switch_mac_addr]
        anomalyIP = pkt.packet_dst_ip_addr
        times+=time.time_ns()
        print("anomaly_switch: "+str(anomalySwitch)+" anomalyIP: "+anomalyIP)
        table_entry = get_match_entry(connectionMap[anomalySwitch], anomalyIP)
        times-=time.time_ns()
        prefix_len = int(table_entry.match[0].lpm.prefix_len)
        lpm_prefix = prefix_len
        egress_port = int.from_bytes(table_entry.action.action.params[1].value, byteorder='big')
        next_switch = portMap[anomalySwitch][egress_port]
        li = []
        li.append(anomalySwitch)
        li.append(next_switch)
        times+=time.time_ns()
        while next_switch!= anomalySwitch:
            table_entry = get_match_entry(connectionMap[next_switch], anomalyIP)
            times-=time.time_ns()
            prefix_len = int(table_entry.match[0].lpm.prefix_len)
            lpm_prefix = max(lpm_prefix, prefix_len)
            egress_port = int.from_bytes(table_entry.action.action.params[1].value, byteorder='big')
            next_switch = portMap[next_switch][egress_port]
            li.append(next_switch)
            times+=time.time_ns()
        loop_info = "->".join(["s"+str(i) for i in li])
        ec_suffix = lpm_prefix
        ec_ip = ip_decode(ip_mask(ip_encode(anomalyIP), ec_suffix))
        print("detected loop: ec "+ec_ip+"/"+str(ec_suffix)+" loop detail "+loop_info)
        times/=1000
        counter.timeTotal+=times
        print("process time"+str(times)+"us")
        print("average process time"+str(counter.timeTotal/counter.cnt)+"us")
        print()


#@profile
def main():
    portMap, deviceMap = topo_loader()
    connectionMap = switch_connection_loader()
    bind_layers(IP,FadInfo,proto=147)
    counter = Counter()
    iface = "s17-eth17"
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x,portMap, deviceMap,connectionMap,counter))

if __name__ == '__main__':
    main()
