package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/refraction-networking/utls"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/idna"
)

func main() {
	maxTtl := flag.Uint("ttl", 30, "Maximum number of hops.")
	connectionMode := flag.String("mode", "", "Connection mode: (syn|http|https).")
	disableIpPtrLookup := flag.Bool("n", false, "Disable IP PTR lookup.")
	timeoutSeconds := flag.Uint("t", 15, "Timeout for each hop.")
	port := flag.Uint("port", 0, "Port number.")
	serverName := flag.String("host", "", "SNI in ClientHello packet or Host header in HTTP request")
	flag.Parse()

	switch *connectionMode {
	case "http", "syn":
		if *port == 0 {
			*port = 80
		}
	case "https":
		if *port == 0 {
			*port = 443
		}
	default:
		switch *port {
		case 80:
			*connectionMode = "http"
		case 443:
			*connectionMode = "https"
		case 0:
			*port = 80
			*connectionMode = "http"
		default:
			*connectionMode = "syn"
		}
	}

	domain := flag.Arg(0)
	if domain == "" {
		fmt.Printf("Specify domain to probe.\n")
		os.Exit(1)
	}

	encodedDomain, err := idna.ToASCII(domain)
	if err != nil {
		fmt.Printf("Unable to ascii encode the given domain: %s", err)
		os.Exit(1)
	}

	if *serverName == "" {
		*serverName = encodedDomain
	} else {
		*serverName, err = idna.ToASCII(*serverName)
	}
	if err != nil {
		fmt.Printf("Unable to ascii encode the given host: %s", err)
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

	livePacketSource, err := startPacketCapture(outgoingPcapInterfaceName, targetIp, *port)
	if err != nil {
		fmt.Printf("Failed to start packet capture on interface '%s': %s\n", outgoingPcapInterfaceName, err)
		os.Exit(3)
	}
	defer livePacketSource.Close()

	var targetConn net.Conn = nil

	var frame gopacket.Packet
	var firstIpPacket *layers.IPv4
	var firstAckTcpPacket *layers.TCP
	var firstIcmpPacket *layers.ICMPv4
	var firstSourceMac *net.HardwareAddr
	var firstTargetMac *net.HardwareAddr

	targetConn, err = net.Dial("tcp", net.JoinHostPort(targetIp.String(), fmt.Sprintf("%d", *port)))
	if err != nil {
		fmt.Printf("Failed to establish connection to %s: %s\n", domain, err)
	}
	if err == nil {
		defer func() { _ = targetConn.Close() }()
	}

	select {
	case frame = <-livePacketSource.PacketChan:
		break
	case <-time.After(time.Second * 5):
		fmt.Printf("Timed out waiting to read the first SYN packet.\n")
		os.Exit(4)
	}

	firstEthernetPacket, _ := frame.LinkLayer().(*layers.Ethernet)
	firstLinuxSllPacket, _ := frame.LinkLayer().(*layers.LinuxSLL)

	if firstEthernetPacket != nil {
		firstSourceMac = &firstEthernetPacket.SrcMAC
		firstTargetMac = &firstEthernetPacket.DstMAC
	} else if firstLinuxSllPacket != nil {
		// Do nothing
	} else {
		fmt.Printf("Unsupported link-layer type: %T\n", frame.LinkLayer())
		os.Exit(3)
	}

	if targetConn != nil {
		select {
		case frame = <-livePacketSource.PacketChan:
			break
		case <-time.After(time.Second * 5):
			fmt.Printf("Timed out waiting to receive the first SYN-ACK packet.\n")
			os.Exit(4)
		}

		firstIpPacket = frame.NetworkLayer().(*layers.IPv4)
		firstAckTcpPacket, _ = frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
		firstIcmpPacket, _ = frame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

		if firstAckTcpPacket == nil {
			if firstIpPacket != nil && firstIcmpPacket != nil {
				fmt.Printf("* Received ICMP TTL exceeded from %s.\n", firstIpPacket.SrcIP.String())
			} else if frame != nil {
				fmt.Printf("* Received unexpected packet: %s\n", frame.TransportLayer())
				os.Exit(5)
			}
		} else if firstAckTcpPacket.RST {
			fmt.Printf("* Received TCP Reset.\n")
			firstAckTcpPacket = nil
		}
	}

	switch *connectionMode {
	case "http":
		fmt.Println("Running in HTTP mode")
		err = runHttpGetTrace(
			firstSourceMac,
			outgoingIp,
			firstTargetMac,
			targetIp,
			*serverName,
			firstAckTcpPacket.DstPort,
			firstAckTcpPacket.Ack,
			firstAckTcpPacket.Seq+1,
			livePacketSource,
			maxTtlByte,
			*disableIpPtrLookup,
			*timeoutSeconds,
			int(*port))
	case "https":
		fmt.Println("Running in HTTPS ClientHello mode")
		// use uTLS library to create a google chrome fingerprinted ClientHello using empty connection
		var conn net.Conn = nil
		uTLSConn := tls.UClient(conn, &tls.Config{ServerName: *serverName}, tls.HelloChrome_Auto)
		var err = uTLSConn.BuildHandshakeState()
		if err != nil {
			return
		}
		var rawClientHello = uTLSConn.HandshakeState.Hello.Raw
		var recordHeader = []byte{0x16, 0x03, 0x01}
		var recordHeaderBytes = make([]byte, 2)
		var clientHelloUInt16 = uint16(len(rawClientHello))
		binary.BigEndian.PutUint16(recordHeaderBytes, clientHelloUInt16)
		var fullClientHello = append(recordHeader, recordHeaderBytes...)
		fullClientHello = append(fullClientHello, rawClientHello...) // append record header + ClientHello size to payload

		err = runClientHelloTrace(
			firstSourceMac,
			outgoingIp,
			firstTargetMac,
			targetIp,
			firstAckTcpPacket.DstPort,
			firstAckTcpPacket.Ack,
			firstAckTcpPacket.Seq+1,
			livePacketSource,
			maxTtlByte,
			*disableIpPtrLookup,
			*timeoutSeconds,
			fullClientHello,
			int(*port))
	case "syn":
		fmt.Println("Running in TCP syn mode")
		if targetConn != nil {
			_ = targetConn.Close()

			for {
				select {
				case frame = <-livePacketSource.PacketChan:
					break
				case <-time.After(time.Second * time.Duration(*timeoutSeconds)):
					fmt.Printf("Timed out waiting to read FIN packet.\n")
					os.Exit(4)
				}

				tcpPacket, _ := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if tcpPacket.FIN {
					break
				}
			}
		}

		err = runTcpSynTrace(
			firstSourceMac,
			outgoingIp,
			firstTargetMac,
			targetIp,
			livePacketSource,
			maxTtlByte,
			*disableIpPtrLookup,
			*timeoutSeconds,
			int(*port))
	}

	if err != nil {
		fmt.Printf("* Probe failure: %s\n", err)
		os.Exit(6)
	}

	fmt.Printf("* Probe complete.\n")
}
