import sys
import csv
import tqdm
import json
sys.path.append("utils")
import switch
sys.path.append("../../utils")
from p4runtime_lib import helper
from p4runtime_lib import convert
from p4.v1 import p4runtime_pb2
from scapy.all import IP, UDP,TCP, Ether, get_if_hwaddr, sendp

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


def is_generator_empty(generator):
    try:
        next(generator)
        return False
    except StopIteration:
        return True

def topo_loader():
    with open("topo/topology.json",'r') as f:
        content = json.load(f)
        portMap = {}
        for link in content["links"]:
            if link[0][0]=='h' or link[1][0]=='h':
                continue
            srcSwitch = int(link[0].split('-')[0][1:])
            srcPort = int(link[0].split('-')[1][1:])
            dstSwitch = int(link[1].split('-')[0][1:])
            if srcSwitch not in portMap:
                portMap[srcSwitch]={}
            portMap[srcSwitch][srcPort] = dstSwitch
        return portMap

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


connectionMap = {}
electionSeriesNumber = 44
for injectionSwitchId in range(1,17):
    hostRpcServerAddr = "127.0.0.1:" + str(50050+injectionSwitchId)
    tableEntryWriteLogFile = "entryLogs/s{}-p4runtime-requests.txt".format(injectionSwitchId)
    connectionMap[injectionSwitchId] = switch.SwitchConnection(str(injectionSwitchId)+"Connection",
                                                address=hostRpcServerAddr, 
                                                device_id=injectionSwitchId-1,
                                                proto_dump_file=tableEntryWriteLogFile)
    connectionMap[injectionSwitchId].MasterArbitrationUpdate(electionSeriesNumber)


#table_name = 

#table_entry = p4info_helper.buildTableEntry(
#        table_name=table_name,
#        match_fields={
#        "hdr.ipv4.dstAddr": ["105.187.0.0", 16]
#        }
#)
#print(next(connectionMap[12].ReadTableEntry(table_entry)))


table_entry = get_match_entry(connectionMap[12],"105.187.0.0")
prefix_len = table_entry.match[0].lpm.prefix_len
egress_port = int.from_bytes(table_entry.action.action.params[1].value, byteorder='big')

portMap = topo_loader()