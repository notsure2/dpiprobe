package main

import (
	"github.com/google/gopacket/pcap"
	"net"
)

func FindPcapInterfaceName(ipAddress net.IP) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	for _, networkInterface := range devices {
		interfaceAddresses := networkInterface.Addresses
		for _, interfaceAddress := range interfaceAddresses {
			interfaceIp := interfaceAddress.IP
			if interfaceIp.Equal(ipAddress) {
				return networkInterface.Name, nil
			}
		}
	}

	return "", nil
}
