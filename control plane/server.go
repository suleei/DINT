package main
 
import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	mapset "github.com/deckarep/golang-set/v2"
	"strings"
	"strconv"
	"fmt"
	"time"
	"runtime"
	"net"
	"os"
	"github.com/dalzilio/rudd"
)
var (
	device       string = "s17-eth17"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	heapMax     float64  = 0
	stackMax     float64  = 0
	memoryMax    float64  = 0
	bdd  		*rudd.BDD
	processedEcSet mapset.Set[rudd.Node]
)

const switchNum int = 16

type Connection struct{
	context context.Context
	client  *client.Client
	conn    *grpc.ClientConn
}

type MatchEntry struct{
	match  int
	prefix int
	port   int
}

var connectionMap map[int]Connection

func ConnectionInit() {
	connectionMap = make(map[int]Connection)
	for i := 0; i<switchNum; i++ {
		ctx := context.Background()
		var addr string = "192.168.139.128:"+strconv.Itoa(50051+i)
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
	matchEntry := MatchEntry{0, 0, 0}
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
			if(int(prefixLen) > matchEntry.prefix){
				matchEntry.prefix = int(prefixLen)
				portSegments := v.Action.GetAction().Params[1].Value
				port := 0
				for _, v := range portSegments{
					port = port*256 + int(v)
				}
				matchEntry.port = port
			}
		}
	}
	timeCost := time.Since(startTime)
	return matchEntry, timeCost
}

func GetMatchEntryAndHigherPriorityEntryByIp(connection Connection, ipAddr string) (MatchEntry, []MatchEntry, time.Duration){
	startTime := time.Now()
	entries, err := connection.client.ReadTableEntryWildcard(connection.context, "MyIngress.ipv4_lpm")
	if err != nil {
		fmt.Println("Read Entries Error: %v", err)
	}
	findIp := IpToInt(ipAddr)
	matchEntry := MatchEntry{0, 0, 0}
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
			if(int(prefixLen) > matchEntry.prefix){
				matchEntry.match = value
				matchEntry.prefix = int(prefixLen)
				portSegments := v.Action.GetAction().Params[1].Value
				port := 0
				for _, v := range portSegments{
					port = port*256 + int(v)
				}
				matchEntry.port = port
			}
		}
	}
	var higherPriorityEntries []MatchEntry
	for _, v := range entries {
		if(v.TableId!=37375156){
			continue
		}
		prefixLen := v.Match[0].GetLpm().PrefixLen
		valueSegments := v.Match[0].GetLpm().Value
		value := 0
		for _, v := range valueSegments{
			value = value*256 + int(v)
		}
		if(int(prefixLen) > matchEntry.prefix && IpMask(value, matchEntry.prefix) == matchEntry.match){
			portSegments := v.Action.GetAction().Params[1].Value
			port := 0
			for _, v := range portSegments{
				port = port*256 + int(v)
			}
			higherPriorityEntries = append(higherPriorityEntries, MatchEntry{value, int(prefixLen), port})
		}
	}
	timeCost := time.Since(startTime)
	return matchEntry, higherPriorityEntries, timeCost
}

func GetMatchBddFormula(entry MatchEntry) rudd.Node {
	bitIndex := 31
	prefix := entry.prefix
	match := entry.match
	res := bdd.True()
	for bitIndex >= 0 {
		if bitIndex+1 <= prefix {
			if match % 2 == 0 {
				res = bdd.And(res, bdd.Ithvar(bitIndex))
			}else {
				res = bdd.And(res, bdd.NIthvar(bitIndex))
			}
		}
		match = match >> 1
		bitIndex -= 1
	}
	return res
}

func GetIpBddFormula(ip string) rudd.Node {
	bitIndex := 31
	match := IpToInt(ip)
	res := bdd.True()
	for bitIndex >= 0 {
		if match % 2 == 0 {
			res = bdd.And(res, bdd.NIthvar(bitIndex))
		}else {
			res = bdd.And(res, bdd.Ithvar(bitIndex))
		}
		match = match >> 1
		bitIndex -= 1
	}
	return res
}

func GetEcBddFormula(matchEntry MatchEntry, higherPriorityEntries []MatchEntry) rudd.Node {
	res := GetMatchBddFormula(matchEntry)
	for _, v := range higherPriorityEntries {
		if matchEntry.port != v.port {
			res = bdd.And(res, bdd.Not(GetMatchBddFormula(v)))
		}
	}
	return res
}

func readMem() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	heapUse := float64(m.Alloc)/1024/1024
	stackUse := float64(m.StackInuse)/1024/1024
	memoryUse := heapUse+stackUse
	heapMax = max(heapMax, heapUse)       
	stackMax = max(stackMax, stackUse)       
	memoryMax = max(memoryMax, memoryUse)   
	fmt.Printf("HeapUse = %v MiB, Max = %v MiB\n", heapUse,heapMax)           
	fmt.Printf("StackUse = %v MiB, Max = %v MiB\n", stackUse,stackMax)    
	fmt.Printf("MemoryUse = %v MiB, Max = %v MiB\n", memoryUse,memoryMax)    
}

func CheckError(err error) {
    if err  != nil {
        fmt.Println("Error: " , err)
        os.Exit(0)
    }
}
 
func main() {
	bdd, _ = rudd.New(32, rudd.Nodesize(10000), rudd.Cachesize(3000))
	processedEcSet = mapset.NewSet[rudd.Node]()
	readMem()
	ConnectionInit()
	defer ConnectionClose()
    ServerAddr,err := net.ResolveUDPAddr("udp",":4242")
    CheckError(err)
 
    ServerConn, err := net.ListenUDP("udp", ServerAddr)
    CheckError(err)
    defer ServerConn.Close()
 
    buf := make([]byte, 1024)
	totalCount := 0
	totalDuration := time.Duration(0)
 
    for {
        _,_,err := ServerConn.ReadFromUDP(buf)
		totalCount += 1
		CheckError(err)
		macAddressSegments := buf[0:6]
		ipAddressSegments := buf[6:10]
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
		packetDstIpBddFormula := GetIpBddFormula(packetDstIpAddr)
		startTime := time.Now()
		processedMarker := false
		for formula := range processedEcSet.Iter(){
			if bdd.And(formula, packetDstIpBddFormula) != bdd.False() {
				processedMarker = true
				break
			}
		}
		var matchEntry MatchEntry
		var higherPriorityEntries []MatchEntry
		var communicationTimeCost time.Duration
		var ecBddFormula rudd.Node
		loopNode := []int{anomalySwichId}
		if !processedMarker {
			matchEntry,higherPriorityEntries,communicationTimeCost = GetMatchEntryAndHigherPriorityEntryByIp(connectionMap[anomalySwichId-1],packetDstIpAddr)
			ecBddFormula = GetEcBddFormula(matchEntry, higherPriorityEntries)
			for matchEntry.port != anomalySwichId {
				loopNode = append(loopNode, matchEntry.port)
				var ctc time.Duration
				matchEntry,higherPriorityEntries,ctc=GetMatchEntryAndHigherPriorityEntryByIp(connectionMap[matchEntry.port-1],packetDstIpAddr)
				ecBddFormula = bdd.And(ecBddFormula, GetEcBddFormula(matchEntry, higherPriorityEntries))
				communicationTimeCost += ctc
			}
			processedEcSet.Add(ecBddFormula)
		}else {
			communicationTimeCost = 0
		}
		timeCost := time.Since(startTime)
		totalDuration += (timeCost-communicationTimeCost)
		// remove immediately since anomaly entry will be delete
		// after injected in evaluation dataset, in order to simulate fix anomalies in data plane
		if !processedMarker {
			processedEcSet.Remove(ecBddFormula)
			fmt.Println("anomalySwitchMacAddr: "+anomalySwitchMacAddr)
			fmt.Println("packetDstIpAddr: "+packetDstIpAddr)
			fmt.Print("Loop:")
			fmt.Println(loopNode)
			fmt.Printf("time cost without communication= %v ns\n", timeCost-communicationTimeCost)
			fmt.Printf("average time cost without communication= %v ns\n", float64(totalDuration.Nanoseconds()) / float64(totalCount))
		}else {
			fmt.Println("anomalySwitchMacAddr: "+anomalySwitchMacAddr)
			fmt.Println("packetDstIpAddr: "+packetDstIpAddr)
			fmt.Print("EC already processed")
			fmt.Printf("average time cost without communication= %v ns\n", float64(totalDuration.Nanoseconds()) / float64(totalCount))
		}
		
		readMem()
    }
}