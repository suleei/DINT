import sys
import csv
import tqdm
sys.path.append("utils")
import switch
sys.path.append("../../utils")
from p4runtime_lib import helper
from scapy.all import IP, UDP,TCP, Ether, get_if_hwaddr, sendp

def writeTableEntry(switchConnection, electionSeriesNumber,type,dstAddr,suffix,dstMac,dstPort):
    p4info_helper = helper.P4InfoHelper("build/basic.p4.p4info.txt")
    table_name = "MyIngress.ipv4_lpm"
    match_fields = {
        "hdr.ipv4.dstAddr": [dstAddr, suffix]
    }
    action_name = "MyIngress.ipv4_forward"
    default_action = None
    action_params = {
        "dstAddr": dstMac,
        "port": dstPort,
        "suffix": suffix
    }
    priority = None
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority
    )
    switchConnection.WriteTableEntry(electionSeriesNumber,table_entry,type)

def deleteTableEntry(switchConnection, electionSeriesNumber,dstAddr,suffix):
    p4info_helper = helper.P4InfoHelper("build/basic.p4.p4info.txt")
    table_name = "MyIngress.ipv4_lpm"
    match_fields = {
        "hdr.ipv4.dstAddr": [dstAddr, suffix]
    }
    action_name = None
    default_action = None
    action_params = None
    priority = None
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority
    )
    switchConnection.DeleteTableEntry(electionSeriesNumber,table_entry)

connectionMap = {}
electionSeriesNumber = 43
for injectionSwitchId in range(1,17):
    hostRpcServerAddr = "127.0.0.1:" + str(50050+injectionSwitchId)
    tableEntryWriteLogFile = "entryLogs/s{}-p4runtime-requests.txt".format(injectionSwitchId)
    connectionMap[injectionSwitchId] = switch.SwitchConnection(str(injectionSwitchId)+"Connection",
                                                address=hostRpcServerAddr, 
                                                device_id=injectionSwitchId-1,
                                                proto_dump_file=tableEntryWriteLogFile)
    connectionMap[injectionSwitchId].MasterArbitrationUpdate(electionSeriesNumber)

with open("data/test.csv","r") as fibUpdateFile, open("data/loopPointRecord.txt") as loopMarkerFile:
    loopMarker = loopMarkerFile.readlines()
    csvReader = csv.reader(fibUpdateFile)
    cnt=0
    statusSet = set()
    for row in tqdm.tqdm(csvReader):
        suffix = int(row[0].split('/')[1])
        dstAddr = row[0][1:].split('/')[0]
        insertSwitch = row[1].split('-')[0][1:]
        dstSwitch = row[2].split('-')[0][1:]
        dstMac = "ff:ff:ff:ff:ff:" + "{:02d}".format(int(dstSwitch))
        dstPort = int(dstSwitch)
        statusKey = dstAddr+"/"+str(suffix)+","+insertSwitch
        if statusKey in statusSet:
            operation = "MODIFY"
        else:
            operation = "INSERT"
            statusSet.add(statusKey)
        writeTableEntry(connectionMap[int(insertSwitch)], electionSeriesNumber,operation,dstAddr,suffix,dstMac,dstPort)
        
        packetTargetSwitch = "s"+insertSwitch+"-eth"+ insertSwitch
        pkt =  Ether(src=get_if_hwaddr(packetTargetSwitch), dst="ff:ff:ff:ff:ff:" + "{:02d}".format(int(insertSwitch)))
        l4_content = TCP(dport=3, sport=3)
        pkt = pkt /IP(src="10.0.0.1",dst=dstAddr) / l4_content / str(str("10.1.1.1")+":"+dstAddr)
        sendp(pkt, iface=packetTargetSwitch, verbose=False)

        if  loopMarker[cnt][0]=="1":
            statusSet.remove(statusKey)
            deleteTableEntry(connectionMap[int(insertSwitch)], electionSeriesNumber,dstAddr,suffix)
        cnt+=1