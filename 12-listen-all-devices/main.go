package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var timeout = 10 * time.Second
var pcapFile = "output.pcap"

func main() {
	_ = os.Remove(pcapFile)
	// Create the output file
	f, err := os.Create(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Create a packet writer
	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(65535, layers.LinkTypeEthernet)

	// Create a channel to pass packets to the writer goroutine
	packets := make(chan gopacket.Packet, 1000)

	// Find all available network interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Create a separate goroutine for each device
	var wg sync.WaitGroup
	wg.Add(len(devices))
	for _, device := range devices {
		fmt.Println("Listening on device", device.Name)
		go func(device pcap.Interface) {
			defer wg.Done()

			handle, err := pcap.OpenLive(device.Name, 65535, true, timeout)
			if err != nil {
				log.Printf("Error opening device %s: %v", device.Name, err)
				return
			}
			defer handle.Close()

			// Start processing packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			// Because OpenLive's timeout is not working well, we need to use a timer
			timer := time.NewTimer(timeout)
			for {
				select {
				case packet := <-packetSource.Packets():
					// fmt.Println("Packet received from device", device.Name)
					packets <- packet
				case <-timer.C:
					log.Printf("Timeout occurred on device %s", device.Name)
					return
				}
			}
		}(device)
	}

	// Wait for all goroutines to finish then close channel
	go func() {
		wg.Wait()
		close(packets)
		log.Printf("All goroutines finished. Closing channel.")
	}()

	// Write packets to file
	count := 0
	for packet := range packets {
		count++
		fmt.Println("Writing packet", count)
		err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Printf("Error writing packet to file: %v", err)
		}
	}
}
