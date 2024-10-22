package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var DeviceName = "en0"
var IsDeviceFound = false
var snapLen int32 = 1600
var promiscuous = false

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln("Unable to find network interfaces")
	}

	for _, device := range devices {
		if device.Name == DeviceName {
			IsDeviceFound = true
			break
		}
	}

	if !IsDeviceFound {
		log.Panicln("Device not found")
	}

	handle, err := pcap.OpenLive(DeviceName, snapLen, promiscuous, pcap.BlockForever)
	if err != nil {
		fmt.Print(err)
		log.Panicln("Unable to open device")
	}

	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		log.Panicln("Unable to set filter")
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range source.Packets() {
		fmt.Println(packet)
	}

}
