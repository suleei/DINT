package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"net"
)

var (
	device       string = "s17-eth17"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	handle       *pcap.Handle
)


func CheckError(err error) {
    if err  != nil {
        fmt.Println("Error: " , err)
    }
}

func main(){
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	CheckError(err)
	defer handle.Close()

    ServerAddr,err := net.ResolveUDPAddr("udp","192.168.139.1:4242")
    CheckError(err)
 
    LocalAddr, err := net.ResolveUDPAddr("udp", "192.168.139.128:4242")
    CheckError(err)
 
    Conn, err := net.DialUDP("udp", LocalAddr, ServerAddr)
    CheckError(err)

    defer Conn.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if(int(ip.Protocol)==147) {
                _,err := Conn.Write(ip.LayerPayload())
                if err != nil {
                    fmt.Println(err)
                }
			}
		}
	}
}