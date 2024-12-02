package main

import (
    "encoding/json"
    "fmt"
	"bufio"
	"os"
	"io"
	mapset "github.com/deckarep/golang-set/v2"
	"strings"
	"strconv"
	"runtime"
	"github.com/dalzilio/rudd"
	"time"
)

var (
	err          error
	heapMax     float64  = 0
	stackMax     float64  = 0
	memoryMax    float64  = 0
	bdd  		*rudd.BDD
	processedEcSet mapset.Set[rudd.Node]
)

type MatchEntry struct{
	Match  int
	Prefix int
	Port   int
}

type LogEntry struct {
	AnomalySwitchMacAddr string
	PacketDstIpAddr		string
	MatchEntries        []MatchEntry
	HigherPriorityEntriesGroup [][]MatchEntry
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

func GetMatchBddFormula(entry MatchEntry) rudd.Node {
	bitIndex := 31
	prefix := entry.Prefix
	match := entry.Match
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
		if matchEntry.Port != v.Port {
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
	totalCount := 0
	reportProcessingCost := time.Duration(0)
	f, err := os.Open("files/log-airtel1.json")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
			   break
			} else {
			   fmt.Println(err)
			}
		}
		var logEntry LogEntry
		err = json.Unmarshal(line, &logEntry)
		if err != nil {
			fmt.Println(err)
		}
		totalCount += 1
		anomalySwichId, err := strconv.Atoi(strings.Split(logEntry.AnomalySwitchMacAddr, ":")[5])
		processStartTime := time.Now()
		packetDstIpBddFormula := GetIpBddFormula(logEntry.PacketDstIpAddr)
		processedMarker := false
		for formula := range processedEcSet.Iter(){
			if bdd.And(formula, packetDstIpBddFormula) != bdd.False() {
				processedMarker = true
				break
			}
		}
		loopNode := []int{anomalySwichId}
		ecBddFormula := bdd.True()
		if !processedMarker {
			for i:=0; i < len(logEntry.MatchEntries); i++ {
				matchEntry := logEntry.MatchEntries[i]
				higherPriorityEntries := logEntry.HigherPriorityEntriesGroup[i]
				loopNode = append(loopNode, matchEntry.Port)
				ecBddFormula = bdd.And(ecBddFormula, GetEcBddFormula(matchEntry, higherPriorityEntries))

			}
			processedEcSet.Add(ecBddFormula)
		}
		processCost := time.Since(processStartTime)
		reportProcessingCost += processCost
		if !processedMarker {
			processedEcSet.Remove(ecBddFormula)
			/*fmt.Println("anomalySwitchMacAddr: "+logEntry.AnomalySwitchMacAddr)
			fmt.Println("packetDstIpAddr: "+logEntry.PacketDstIpAddr)
			fmt.Print("Loop:")
			fmt.Println(loopNode)*/
		}/*else {
			fmt.Println("anomalySwitchMacAddr: "+logEntry.AnomalySwitchMacAddr)
			fmt.Println("packetDstIpAddr: "+logEntry.PacketDstIpAddr)
			fmt.Print("EC already processed")
		}
		readMem()
		fmt.Println()*/
	}
	readMem()
	fmt.Printf("average time cost without communication= %v us\n", float64(reportProcessingCost.Nanoseconds()) / float64(totalCount) / 1000)
}