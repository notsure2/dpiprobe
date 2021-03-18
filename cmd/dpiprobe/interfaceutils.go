package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// FindPcapInterfaceName Finds interface name for packet capture using an IP address
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

// findOutgoingPcapInterfaceNameAndIp Finds outgoing interface name and IP for packet capture
func findOutgoingPcapInterfaceNameAndIp(targetIp *net.IPAddr) (string, *net.IPAddr, error) {
	initialConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: targetIp.IP, Port: 443})
	if err != nil {
		return "", nil, err
	}

	localInterfaceIp := initialConn.LocalAddr().(*net.UDPAddr).IP
	_ = initialConn.Close()

	outgoingPcapInterfaceName, err := FindPcapInterfaceName(localInterfaceIp)
	if err != nil {
		return "", nil, err
	}
	if outgoingPcapInterfaceName == "" {
		return "", nil, fmt.Errorf("Unable to lookup the outgoing interface for local IP: %s", localInterfaceIp)
	}

	_, localNet, _ := net.ParseCIDR("127.0.0.0/8")
	if localNet.Contains(localInterfaceIp) {
		return "", nil, errors.New(
			"Outgoing interface is local. Either the destination is the local machine or a" +
				" local proxy is being used.\nPlease choose a remote destination or exclude this app from being" +
				" proxied and try again.")
	}

	return outgoingPcapInterfaceName, &net.IPAddr{IP: localInterfaceIp}, nil
}
