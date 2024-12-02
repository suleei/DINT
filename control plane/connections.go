package main
 
import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"strings"
	"strconv"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"time"
	"runtime"
)
var (
	device       string = "s17-eth17"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	handle       *pcap.Handle
)

const switchNum int = 16

type Connection struct{
	context context.Context
	client  *client.Client
	conn    *grpc.ClientConn
}

type MatchEntry struct{
	prefix int
	port   int
}

var connectionMap map[int]Connection

func ConnectionInit() {
	connectionMap = make(map[int]Connection)
	for i := 0; i<switchNum; i++ {
		ctx := context.Background()
		var addr string = "127.0.0.1:"+strconv.Itoa(50051+i)
		var deviceID uint64 = uint64(i)
		fmt.Println("Connecting to server at %s", addr)
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("Cannot connect to server: %v", err)
		}
		c := p4_v1.NewP4RuntimeClient(conn)
		electionID := &p4_v1.Uint128{High: 0, Low: 43}
		p4RtC := client.NewClient(c, deviceID, electionID)
		connectionMap[i] = Connection{ctx, p4RtC, conn}
	}
}

func ConnectionClose(){
	for i := 0; i<switchNum; i++ {
		connectionMap[i].conn.Close()
	}
}
func IpToBytes(ip string) []byte {
	var res []byte
	for _, v := range strings.Split(ip, "."){
		intValue, _ := strconv.Atoi(v)
		res = append(res, byte(intValue))
	}
	return res
}

func IpToInt(ip string) int {
	bytes := IpToBytes(ip)
	res := 0
	for _, v := range bytes{
		res = res*256 + int(v)
	}
	return res
}

func IpMask(ip int, prefix int) int {
	maskBitLen := 32 - prefix
	return (ip >> maskBitLen) << maskBitLen
}

func GetMatchEntryByIp(connection Connection, ipAddr string) (MatchEntry,time.Duration){
	startTime := time.Now()
	entries, err := connection.client.ReadTableEntryWildcard(connection.context, "MyIngress.ipv4_lpm")
	if err != nil {
		fmt.Println("Read Entries Error: %v", err)
	}
	findIp := IpToInt(ipAddr)
	maxPrefix := 0
	egressPort := 0
	for _, v := range entries{
		if(v.TableId!=37375156){
			continue
		}
		prefixLen := v.Match[0].GetLpm().PrefixLen
		valueSegments := v.Match[0].GetLpm().Value
		value := 0
		for _, v := range valueSegments{
			value = value*256 + int(v)
		}
		if(IpMask(findIp, int(prefixLen))==value){
			if(int(prefixLen) > maxPrefix){
				maxPrefix = int(prefixLen)
				portSegments := v.Action.GetAction().Params[1].Value
				port := 0
				for _, v := range portSegments{
					port = port*256 + int(v)
				}
				egressPort = port
			}
		}
	}
	timeCost := time.Since(startTime)
	return MatchEntry{maxPrefix, egressPort}, timeCost
}

func readMem() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB\n", m.Alloc/1024/1024)           
	fmt.Printf("Sys = %v MiB\n", m.Sys/1024/1024)               
	fmt.Printf("HeapAlloc = %v MiB\n", m.HeapAlloc/1024/1024)   
	fmt.Printf("HeapSys = %v MiB\n", m.HeapSys/1024/1024)       
}

func main() {
	readMem()
	ConnectionInit()
	defer ConnectionClose()
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
	}
	defer handle.Close()
 
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if(int(ip.Protocol)==147) {
				macAddressSegments := ip.LayerPayload()[0:6]
				ipAddressSegments := ip.LayerPayload()[6:10]
				var macAddressValues[] string
				var ipAddressValues [] string
				for _, v := range macAddressSegments{
					macAddressValues = append(macAddressValues, fmt.Sprintf("%02x", int(v)))
				}
				for _, v := range ipAddressSegments{
					ipAddressValues = append(ipAddressValues, strconv.Itoa(int(v)))
				}
				anomalySwitchMacAddr := strings.Join(macAddressValues, ":")
				packetDstIpAddr := strings.Join(ipAddressValues, ".")
				anomalySwichId, _ := strconv.Atoi(macAddressValues[5])
				startTime := time.Now()
				matchEntry, communicationTimeCost :=GetMatchEntryByIp(connectionMap[anomalySwichId-1],packetDstIpAddr)
				loopNode := []int{anomalySwichId}
				for matchEntry.port != anomalySwichId {
					loopNode = append(loopNode, matchEntry.port)
					var ctc time.Duration
					matchEntry, ctc =GetMatchEntryByIp(connectionMap[matchEntry.port-1],packetDstIpAddr)
					communicationTimeCost += ctc
				}
				timeCost := time.Since(startTime)
				fmt.Println("anomalySwitchMacAddr: "+anomalySwitchMacAddr)
				fmt.Println("packetDstIpAddr: "+packetDstIpAddr)
				fmt.Println("Loop:")
				fmt.Println(loopNode)
				fmt.Printf("time cost = %v\n", timeCost-communicationTimeCost)
				readMem()
			}
		}
	}
}