// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the Ethereum Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"golang.org/x/exp/slog"
	"io"
)

func main() {
	var (
		listenAddr     = flag.String("addr", ":30301", "listen address")
		genKey         = flag.String("genkey", "", "generate a node key")
		writeAddr      = flag.Bool("writeaddress", false, "write out the node's public key and quit")
		nodeKeyFile    = flag.String("nodekey", "", "private key filename")
		nodeKeyHex     = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc        = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>)")
		netrestrict    = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5          = flag.Bool("v5", true, "run a v5 topic discovery bootnode")
		runv4          = flag.Bool("v4", false, "run a v4 topic discovery bootnode")
		verbosity      = flag.Int("verbosity", 3, "log verbosity (0-5)")
		vmodule        = flag.String("vmodule", "", "log verbosity pattern")
		network        = flag.String("network", "", "testnet/mainnet")
		staticP2pNodes = flag.String("staticnodes", "", "static p2p nodes for discovery")
		nodeKey        *ecdsa.PrivateKey
		err            error
	)

	var staticV4Nodes []v4wire.Node

	flag.Parse()

	//set log
	var (
		handler        slog.Handler
		glogger        *log.GlogHandler
		terminalOutput = io.Writer(os.Stderr)
		output         io.Writer
		logOutputFile  io.WriteCloser
	)

	logFile := "/Users/zhaoxueliang/opbnb_project_pr/geth_bootnode.log"
	if logOutputFile, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err != nil {
		utils.Fatalf("err: %v", err)
	}
	output = io.MultiWriter(logOutputFile, terminalOutput)

	handler = log.LogfmtHandler(output)
	glogger = log.NewGlogHandler(handler)

	slogVerbosity := log.FromLegacyLevel(*verbosity)
	glogger.Verbosity(slogVerbosity)
	glogger.Vmodule(*vmodule)
	log.SetDefault(log.NewLogger(glogger))

	natm, err := nat.Parse(*natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}
	switch {
	case *genKey != "":
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		if !*writeAddr {
			return
		}
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		utils.Fatalf("Use -nodekey or -nodekeyhex to specify a private key")
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		utils.Fatalf("Options -nodekey and -nodekeyhex are mutually exclusive")
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			utils.Fatalf("-nodekey: %v", err)
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	if *staticP2pNodes == "" {
		if *network == "testnet" {
			staticV4Nodes = staticV4NodesTestnet
		} else {
			staticV4Nodes = staticV4NodesMainnet
		}
	} else {
		parsedNodes, err := parseStaticNodes(*staticP2pNodes)
		if err == nil {
			staticV4Nodes = parsedNodes
		} else {
			utils.Fatalf("-staticnodes: %v", err)
		}
	}

	if *writeAddr {
		fmt.Printf("%x\n", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
		os.Exit(0)
	}

	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			utils.Fatalf("-netrestrict: %v", err)
		}
	}

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		utils.Fatalf("-ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Fatalf("-ListenUDP: %v", err)
	}
	defer conn.Close()

	db, _ := enode.OpenDB("")
	ln := enode.NewLocalNode(db, nodeKey)

	listenerAddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil && !listenerAddr.IP.IsLoopback() {
		natAddr := doPortMapping(natm, ln, listenerAddr)
		if natAddr != nil {
			listenerAddr = natAddr
		}
	}

	printNotice(&nodeKey.PublicKey, *listenerAddr)

	//support v4 & v5
	var (
		sharedconn discover.UDPConn = conn
		unhandled  chan discover.ReadPacket
	)

	if !*runv5 && !*runv4 {
		utils.Fatalf("%v", fmt.Errorf("at least one protocol need to be set (v4/v5)"))
	}

	// If both versions of discovery are running, setup a shared
	// connection, so v5 can read unhandled messages from v4.
	if *runv5 && *runv4 {
		unhandled = make(chan discover.ReadPacket, 100)
		sharedconn = p2p.NewSharedUDPConn(conn, unhandled)
	}

	// Start discovery services.
	if *runv4 {
		cfg := discover.Config{
			PrivateKey:    nodeKey,
			NetRestrict:   restrictList,
			Unhandled:     unhandled,
			StaticV4Nodes: staticV4Nodes,
		}
		_, err := discover.ListenV4(conn, ln, cfg)
		log.Info("discv4 protocol enabled")
		if err != nil {
			utils.Fatalf("%v", err)
		}
	}
	if *runv5 {
		cfg := discover.Config{
			PrivateKey:  nodeKey,
			NetRestrict: restrictList,
		}
		_, err := discover.ListenV5(sharedconn, ln, cfg)
		log.Info("discv5 protocol enabled")
		if err != nil {
			utils.Fatalf("%v", err)
		}
	}

	select {}
}

func printNotice(nodeKey *ecdsa.PublicKey, addr net.UDPAddr) {
	if addr.IP.IsUnspecified() {
		addr.IP = net.IP{127, 0, 0, 1}
	}
	n := enode.NewV4(nodeKey, addr.IP, 0, addr.Port)
	fmt.Println(n.URLv4())
	fmt.Println("Note: you're using cmd/bootnode, a developer tool.")
	fmt.Println("We recommend using a regular node as bootstrap node for production deployments.")
}

func doPortMapping(natm nat.Interface, ln *enode.LocalNode, addr *net.UDPAddr) *net.UDPAddr {
	const (
		protocol = "udp"
		name     = "ethereum discovery"
	)
	newLogger := func(external int, internal int) log.Logger {
		return log.New("proto", protocol, "extport", external, "intport", internal, "interface", natm)
	}

	var (
		intport    = addr.Port
		extaddr    = &net.UDPAddr{IP: addr.IP, Port: addr.Port}
		mapTimeout = nat.DefaultMapTimeout
		log        = newLogger(addr.Port, intport)
	)
	addMapping := func() {
		// Get the external address.
		var err error
		extaddr.IP, err = natm.ExternalIP()
		if err != nil {
			log.Debug("Couldn't get external IP", "err", err)
			return
		}
		// Create the mapping.
		p, err := natm.AddMapping(protocol, extaddr.Port, intport, name, mapTimeout)
		if err != nil {
			log.Debug("Couldn't add port mapping", "err", err)
			return
		}
		if p != uint16(extaddr.Port) {
			extaddr.Port = int(p)
			log = newLogger(extaddr.Port, intport)
			log.Info("NAT mapped alternative port")
		} else {
			log.Info("NAT mapped port")
		}
		// Update IP/port information of the local node.
		ln.SetStaticIP(extaddr.IP)
		ln.SetFallbackUDP(extaddr.Port)
	}

	// Perform mapping once, synchronously.
	log.Info("Attempting port mapping")
	addMapping()

	// Refresh the mapping periodically.
	go func() {
		refresh := time.NewTimer(mapTimeout)
		defer refresh.Stop()
		for range refresh.C {
			addMapping()
			refresh.Reset(mapTimeout)
		}
	}()

	return extaddr
}

// parseStaticNodes parses a comma-separated list of node URLs into a slice of Node structs.
func parseStaticNodes(nodeList string) ([]v4wire.Node, error) {
	nodes := strings.Split(nodeList, ",")
	var result []v4wire.Node

	for _, node := range nodes {
		// Trim spaces that might surround the node entry
		node = strings.TrimSpace(node)
		if node == "" {
			continue
		}

		// Parse the node URL
		if !strings.HasPrefix(node, "enode://") {
			return nil, fmt.Errorf("parse error: node does not start with 'enode://'")
		}

		// Separate the node ID from the IP and port
		atPos := strings.Index(node, "@")
		if atPos == -1 {
			return nil, fmt.Errorf("parse error: '@' not found in node string")
		}

		idPart := node[8:atPos] // skip "enode://"
		ipPortPart := node[atPos+1:]

		colonPos := strings.LastIndex(ipPortPart, ":")
		if colonPos == -1 {
			return nil, fmt.Errorf("parse error: ':' not found in IP:port part")
		}

		ipStr := ipPortPart[:colonPos]
		portStr := ipPortPart[colonPos+1:]

		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse error: invalid port number")
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("parse error: invalid IP address")
		}

		nodeStruct := v4wire.Node{
			IP:  ip,
			UDP: uint16(port),
			TCP: uint16(port),
			ID:  decodePubkeyV4(idPart),
		}

		result = append(result, nodeStruct)
	}

	return result, nil
}
