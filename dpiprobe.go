package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/idna"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	maxTtl := flag.Uint("ttl", 128, "Maximum number of hops.")
	tcpSynTrace := flag.Bool("syn", false, "Force TCP SYN trace.")
	disableIpPtrLookup := flag.Bool("n", false, "Disable IP PTR lookup.")
	timeoutSeconds := flag.Uint("t", 15, "Timeout for each hop.")
	flag.Parse()

	domain := flag.Arg(0)
	if domain == "" {
		fmt.Printf("Specify blocked domain to probe with http.\n")
		os.Exit(1)
	}

	encodedDomain, err := idna.ToASCII(domain)
	if err != nil {
		fmt.Printf("Unable to ascii encode the given domain: %s", err)
		os.Exit(1)
	}

	if *maxTtl < 1 {
		fmt.Printf("Maximum number of hops must be 1 or greater.\n")
		os.Exit(1)
	}

	maxTtlByte := uint8(*maxTtl)

	if *maxTtl > 255 {
		fmt.Printf("Maximum number of hops cannot exceed 255.\n")
		os.Exit(1)
	}

	if *timeoutSeconds < 1 {
		fmt.Printf("Timeout must be greater than 0.\n")
		os.Exit(1)
	}

	targetIp, err := net.ResolveIPAddr("ip", encodedDomain)
	if err != nil {
		fmt.Printf("Failed to resolve target domain to IP address: %s\n", err)
		os.Exit(2)
	}

	outgoingPcapInterfaceName, outgoingIp, err := findOutgoingPcapInterfaceNameAndIp(targetIp)
	if err != nil {
		fmt.Printf("Outgoing interface lookup error: %s\n", err)
		os.Exit(2)
	}

	livePacketSource, err := startPacketCapture(outgoingPcapInterfaceName, targetIp)
	if err != nil {
		fmt.Printf("Failed to start packet capture on interface '%s': %s\n", outgoingPcapInterfaceName, err)
		os.Exit(3)
	}
	defer livePacketSource.Close()

	var targetConn net.Conn = nil

	var doDpiTrace = true
	var firstFrame gopacket.Packet
	var firstAckTcpPacket *layers.TCP

	targetConn, err = net.Dial("tcp", net.JoinHostPort(targetIp.String(), "80"))
	if err != nil {
		fmt.Printf("Failed to establish connection to %s: %s\n", domain, err)
		os.Exit(3)
	}
	defer func() { _ = targetConn.Close() }()

	select {
	case firstFrame = <-livePacketSource.PacketChan:
		break
	case <-time.After(time.Second * 5):
		fmt.Printf("Timed out waiting to receive first ACK packet. A firewall" +
			" is blocking the connection or connectivity has been lost. Try normal traceroute or tcp traceroute.\n")
		os.Exit(4)
	}

	var firstSourceMac *net.HardwareAddr
	var firstTargetMac *net.HardwareAddr

	firstEthernetPacket, _ := firstFrame.LinkLayer().(*layers.Ethernet)
	firstLinuxSllPacket, _ := firstFrame.LinkLayer().(*layers.LinuxSLL)

	if firstEthernetPacket != nil {
		firstSourceMac = &firstEthernetPacket.SrcMAC
		firstTargetMac = &firstEthernetPacket.DstMAC
	} else if firstLinuxSllPacket != nil {
		// Do nothing
	} else {
		fmt.Printf("Unsupported link-layer type: %T\n", firstFrame.LinkLayer())
		os.Exit(3)
	}

	firstIpPacket := firstFrame.NetworkLayer().(*layers.IPv4)
	firstAckTcpPacket, _ = firstFrame.Layer(layers.LayerTypeTCP).(*layers.TCP)
	firstIcmpPacket, _ := firstFrame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	if firstAckTcpPacket == nil {
		if firstIcmpPacket != nil {
			fmt.Printf("* Received ICMP TTL exceeded from %s.\n", firstIpPacket.SrcIP.String())
			doDpiTrace = false
		} else {
			fmt.Printf("* Received unexpected packet: %s\n", firstFrame.TransportLayer())
			os.Exit(5)
		}
	} else if firstAckTcpPacket.RST {
		fmt.Printf("* Received TCP Reset.\n")
		doDpiTrace = false
	}

	if *tcpSynTrace || !doDpiTrace || firstAckTcpPacket == nil {
		if *tcpSynTrace {
			fmt.Printf("* Performing TCP SYN traceroute.\n")
		} else {
			fmt.Printf("* TCP connection failed. Performing TCP SYN traceroute.\n")
		}

		livePacketSource.Close()
		_ = targetConn.Close()
		time.Sleep(5 * time.Second)

		livePacketSource, err := startPacketCapture(outgoingPcapInterfaceName, targetIp)
		if err != nil {
			fmt.Printf("Failed to start packet capture on interface '%s': %s\n", outgoingPcapInterfaceName, err)
			os.Exit(3)
		}
		defer livePacketSource.Close()

		err = runTcpSynTrace(
			firstTargetMac,
			outgoingIp,
			firstSourceMac,
			targetIp,
			livePacketSource,
			maxTtlByte,
			*disableIpPtrLookup,
			*timeoutSeconds)
	} else if doDpiTrace {
		fmt.Printf("* TCP connection established. Performing HTTP GET traceroute.\n")
		err = runHttpGetTrace(
			firstTargetMac,
			outgoingIp,
			firstSourceMac,
			targetIp,
			encodedDomain,
			firstAckTcpPacket.DstPort,
			firstAckTcpPacket.Ack,
			firstAckTcpPacket.Seq+1,
			livePacketSource,
			maxTtlByte,
			*disableIpPtrLookup,
			*timeoutSeconds)
	} else {
		err = errors.New("unexpected logic condition - definitely a bug")
	}

	if err != nil {
		fmt.Printf("* Probe failure: %s\n", err)
		os.Exit(6)
	}

	fmt.Printf("* Probe complete.")
}

func findOutgoingPcapInterfaceNameAndIp(targetIp *net.IPAddr) (string, *net.IPAddr, error) {
	initialConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: targetIp.IP})
	if err != nil {
		return "", nil, err
	}

	localInterfaceIp := initialConn.LocalAddr().(*net.UDPAddr).IP
	_ = initialConn.Close()

	outgoingPcapInterfaceName, err := FindPcapInterfaceName(localInterfaceIp)
	if err != nil {
		return "", nil, err
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

func startPacketCapture(outgoingInterfaceName string, targetIp *net.IPAddr) (pcapSource *LivePacketSource, err error) {
	liveHandle, err := pcap.OpenLive(outgoingInterfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	targetIpInt := big.NewInt(0)
	targetIpInt.SetBytes(targetIp.IP.To4())
	targetIpHex := hex.EncodeToString(targetIpInt.Bytes())

	captureFilter := fmt.Sprintf(
		"(tcp and src %s and port 80 and (tcp[tcpflags] & (tcp-ack|tcp-rst|tcp-fin) != 0)) or"+
			" (icmp[icmptype] == icmp-timxceed and icmp[17] == 6 and icmp[24:4] == 0x%s and icmp[30:2] == 80)",
		targetIp.String(),
		targetIpHex)
	if err := liveHandle.SetBPFFilter(captureFilter); err != nil {
		liveHandle.Close()
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(liveHandle, liveHandle.LinkType())
	pcapSource = &LivePacketSource{PacketChan: packetSource.Packets(), PcapHandle: liveHandle}

	return pcapSource, nil
}

type LivePacketSource struct {
	PacketChan chan gopacket.Packet
	PcapHandle *pcap.Handle
}

func (p *LivePacketSource) Close() {
	p.PcapHandle.Close()
}

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
	timeoutSeconds uint) error {

	return runTrace(
		tcpAckNumber,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer *layers.Ethernet = nil
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
				DstPort: layers.TCPPort(80),
				Seq:     tcpSeqNumber,
				Ack:     tcpAckNumber,
				Window:  255,
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

func runTcpSynTrace(
	sourceMac *net.HardwareAddr,
	sourceIp *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIp *net.IPAddr,
	livePacketSource *LivePacketSource,
	maxTtl uint8,
	disableIpPtrLookup bool,
	timeoutSeconds uint) error {
	return runTrace(
		0,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer *layers.Ethernet = nil
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
				DstPort: layers.TCPPort(80),
				Seq:     rand.Uint32(),
				Ack:     0,
				Window:  uint16(uint8(rand.Uint32())),
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

	for ttl := uint8(1); ttl < maxTtl; ttl++ {
		fmt.Printf("%d. ", ttl)

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

			if frame == nil {
				break
			}

			ipPacket := frame.NetworkLayer().(*layers.IPv4)
			tcpPacket, _ := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
			icmpPacket, _ := frame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

			if ipPacket == nil {
				return errors.New(fmt.Sprintf("Unexpected packet: %s", frame))
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
				if tcpPacket.Seq == firstAckSeqNumber && !tcpPacket.FIN && !tcpPacket.RST {
					continue
				}

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

				fmt.Printf("%s %s[TCP %s]\n", ipPacket.SrcIP, ipSourceDnsNameFragment, tcpFlag)

				if tcpPacket.FIN {
					return errors.New("remote peer actively closed the connection")
				}

				breakOuter = true
				break
			}

			if icmpPacket != nil {
				fmt.Printf("%s %s\n", ipPacket.SrcIP, ipSourceDnsNameFragment)
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

	fmt.Printf("%s", linkLayer)
	if linkLayer != nil {
		if err := transportLayer.SetNetworkLayerForChecksum(&networkLayer); err != nil {
			return err
		}
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

	conn, err := net.Dial("ip4:tcp", networkLayer.DstIP.String())
	if err != nil {
		return err
	}
	opts.ComputeChecksums = false
	if err := gopacket.SerializeLayers(buffer, opts, &transportLayer, gopacket.Payload(tcpPayload)); err != nil {
		return err
	}
	if _, err = conn.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}
