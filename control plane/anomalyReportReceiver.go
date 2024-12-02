package main
 
import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"strings"
	"strconv"
)
 
var (
	device       string = "s17-eth17"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	handle       *pcap.Handle
)

 
func main() {
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
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
				fmt.Println("anomalySwitchMacAddr: "+anomalySwitchMacAddr)
				fmt.Println("packetDstIpAddr: "+packetDstIpAddr)
				fmt.Println()
			}
		}
	}
}