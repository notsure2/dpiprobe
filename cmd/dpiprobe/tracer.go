package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

func runHttpGetTrace(
	sourceMac *net.HardwareAddr,
	sourceIp *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIp *net.IPAddr,
	domain string,
	sourcePort layers.TCPPort,
	tcpSeqNumber uint32,
	tcpAckNumber uint32,
	livePacketSource *LivePacketSource,
	maxTtl uint8,
	disableIpPtrLookup bool,
	timeoutSeconds uint,
	port int) error {

	return runTrace(
		tcpAckNumber,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIp.IP,
				DstIP:    targetIp.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: sourcePort,
				DstPort: layers.TCPPort(port),
				Seq:     tcpSeqNumber,
				Ack:     tcpAckNumber,
				Window:  1450,
				ACK:     true,
				PSH:     true,
			}
			tcpPayload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", domain))
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, tcpPayload); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTtl,
		disableIpPtrLookup,
		timeoutSeconds)
}

func runClientHelloTrace(
	sourceMac *net.HardwareAddr,
	sourceIp *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIp *net.IPAddr,
	sourcePort layers.TCPPort,
	tcpSeqNumber uint32,
	tcpAckNumber uint32,
	livePacketSource *LivePacketSource,
	maxTtl uint8,
	disableIpPtrLookup bool,
	timeoutSeconds uint,
	rawClientHello []byte,
	port int) error {

	return runTrace(
		tcpAckNumber,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIp.IP,
				DstIP:    targetIp.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: sourcePort,
				DstPort: layers.TCPPort(port),
				Seq:     tcpSeqNumber,
				Ack:     tcpAckNumber,
				Window:  1450,
				ACK:     true,
				PSH:     true,
			}
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, rawClientHello); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTtl,
		disableIpPtrLookup,
		timeoutSeconds)
}

func runTcpSynTrace(
	sourceMac *net.HardwareAddr,
	sourceIp *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIp *net.IPAddr,
	livePacketSource *LivePacketSource,
	maxTtl uint8,
	disableIpPtrLookup bool,
	timeoutSeconds uint,
	port int) error {
	return runTrace(
		0,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIp.IP,
				DstIP:    targetIp.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: layers.TCPPort(uint16(rand.Uint32())),
				DstPort: layers.TCPPort(port),
				Seq:     rand.Uint32(),
				Ack:     0,
				Window:  1450,
				SYN:     true,
			}
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, []byte{}); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTtl,
		disableIpPtrLookup,
		timeoutSeconds)
}

func runTrace(
	firstAckSeqNumber uint32,
	sendProbeFunc func(handle *pcap.Handle, ttl uint8) error,
	livePacketSource *LivePacketSource,
	maxTtl uint8,
	disableIpPtrLookup bool,
	timeoutSeconds uint) error {

	for ttl := uint8(1); ttl <= maxTtl; ttl++ {
		fmt.Printf("%d. ", ttl)

		var start = time.Now()

		if err := sendProbeFunc(livePacketSource.PcapHandle, ttl); err != nil {
			return err
		}

		var breakOuter = false
		for {
			var frame gopacket.Packet
			select {
			case frame = <-livePacketSource.PacketChan:
				break
			case <-time.After(time.Second * time.Duration(timeoutSeconds)):
				fmt.Printf("*\n")
				break
			}

			var elapsedTime = time.Since(start)

			if frame == nil {
				break
			}

			ipPacket := frame.NetworkLayer().(*layers.IPv4)
			tcpPacket, _ := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
			icmpPacket, _ := frame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

			if ipPacket == nil {
				return errors.New(fmt.Sprintf("Unexpected packet: %s", frame))
			}

			if tcpPacket != nil &&
				((tcpPacket.Seq == firstAckSeqNumber && !tcpPacket.FIN && !tcpPacket.RST) ||
					(tcpPacket.SYN && !tcpPacket.ACK)) {
				continue
			}

			var ipSourceDnsNameFragment = ""
			if !disableIpPtrLookup {
				ipSourceDnsNames, _ := net.LookupAddr(ipPacket.SrcIP.String())
				if ipSourceDnsNames == nil {
					ipSourceDnsNames = []string{}
				}
				if len(ipSourceDnsNames) > 0 {
					dnsName := strings.TrimRight(ipSourceDnsNames[0], ".")
					ipSourceDnsNameFragment = "(" + dnsName + ") "
				}
			}

			if tcpPacket != nil {
				var tcpFlag = "(unexpected flag)"
				if tcpPacket.ACK {
					if tcpPacket.SYN {
						tcpFlag = "SYN-ACK"
					} else if tcpPacket.FIN {
						tcpFlag = "FIN-ACK"
					} else if tcpPacket.RST {
						tcpFlag = "RST-ACK"
					} else {
						tcpFlag = "ACK"
					}
				} else if tcpPacket.RST {
					tcpFlag = "RST"
				}

				fmt.Printf("%s %s[TCP %s] %s\n", ipPacket.SrcIP, ipSourceDnsNameFragment, tcpFlag, elapsedTime)

				if tcpPacket.FIN {
					return errors.New("remote peer actively closed the connection")
				}

				breakOuter = true
				break
			}

			if icmpPacket != nil {
				fmt.Printf("%s %s%s\n", ipPacket.SrcIP, ipSourceDnsNameFragment, elapsedTime)
				break
			}
		}

		if breakOuter {
			break
		}
	}

	return nil
}

func sendRawPacket(
	pcapHandle *pcap.Handle,
	linkLayer gopacket.SerializableLayer,
	networkLayer layers.IPv4,
	transportLayer layers.TCP,
	tcpPayload []byte) error {

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := transportLayer.SetNetworkLayerForChecksum(&networkLayer); err != nil {
		return err
	}

	if linkLayer != nil {
		if err := gopacket.SerializeLayers(
			buffer,
			opts,
			linkLayer,
			&networkLayer,
			&transportLayer,
			gopacket.Payload(tcpPayload)); err != nil {
			return err
		}
		if err := pcapHandle.WritePacketData(buffer.Bytes()); err != nil {
			return err
		}

		return nil
	}

	conn, err := net.Dial("ip4:tcp", networkLayer.DstIP.String()+":"+fmt.Sprintf("%d", transportLayer.DstPort))
	if err != nil {
		return err
	}
	ipConn := ipv4.NewConn(conn)
	if err := ipConn.SetTTL(int(networkLayer.TTL)); err != nil {
		return err
	}
	if err := gopacket.SerializeLayers(buffer, opts, &transportLayer, gopacket.Payload(tcpPayload)); err != nil {
		return err
	}
	if _, err = conn.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}
