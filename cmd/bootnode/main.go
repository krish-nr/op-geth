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
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

func main() {
	var (
		listenAddr  = flag.String("addr", ":30301", "listen address")
		genKey      = flag.String("genkey", "", "generate a node key")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's public key and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5       = flag.Bool("v5", false, "run a v5 topic discovery bootnode")
		verbosity   = flag.Int("verbosity", int(log.LvlInfo), "log verbosity (0-5)")
		vmodule     = flag.String("vmodule", "", "log verbosity pattern")
		network     = flag.String("network", "", "testnet/mainnet")

		nodeKey *ecdsa.PrivateKey
		err     error
	)

	var staticV4Nodes []v4wire.Node

	var staticV4NodesTestnet = []v4wire.Node{
		//p2p-0

		{
			IP:  net.ParseIP("18.177.245.157").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("223488870e492f49873b621c21f3e1302f00993aaa5214a077a1c4eb62dfe96675cc7a3360525c3409480d1ec13cc72f432b4d50f5e70f98e60385dc25d4be6b"),
		},

		//p2p-1
		{
			IP:  net.ParseIP("18.176.219.164").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("f6a082e7861762da7e5d65ebf92b06e72b9fde81787a1a71ec8ab407345f3a7787e2617c5b9565ea3a1be46f794eeb791aef3059818b23588f2352b1d7973dfd"),
		},
	}

	var staticV4NodesMainnet = []v4wire.Node{
		//ap-p2p-0

		{
			IP:  net.ParseIP("52.193.218.151").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("db109c6cac5c8b6225edd3176fc3764c58e0720950fe94c122c80978e706a9c9e976629b718e48b6306ea0f9126e5394d3424c9716c5703549e2e7eba216353b"),
		},

		//ap-p2p-1
		{
			IP:  net.ParseIP("52.195.105.192").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("afe18782053bb31fb7ea41e1acf659ab9bd1eec181fb97331f0a6b61871a469b4f75138f903c977796be1cc2a3c985d33150a396e878d3cd6e4723b6040ff9c0"),
		},
		//ap-p2p-2
		{
			IP:  net.ParseIP("18.182.161.116").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("0cbbf05d39193127e373038f41cdfb520644453dc764bac49f8403b774f2aab7e679b72ac1ee692f19f55cf07cdf07ef99195c841cbe30d263955149de9213cb"),
		},
		//us-p2p-2
		{
			IP:  net.ParseIP("34.205.6.198").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("ad16edbb25953c36026636427d637fd874f65d1895a589c987009cb820a675cb0f0e1a1dffe34b826a8ef4cc9a0da398cc921ce612de7e6167dd3fdf3db9a1d9"),
		},
		//us-p2p-1
		{
			IP:  net.ParseIP("34.194.74.36").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("852a9d69b385ccf858227ab741d73821704b7fc4abf6510840e8769a44c0d360d269a6ff6b0c42d7335e1caa494a16e45e24ad8aaa9830509f1d8ff49ebb1288"),
		},
		//us-p2p-0
		{
			IP:  net.ParseIP("54.211.157.22").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("23538322b4fa60a936395012b37d5b4407717eec54c64232bd4e985b24ad941c3e4dd36d634e053286d926ceed66c725f8f2a72003f59901b963dee9d9983080"),
		},
		//eu-p2p-0
		{
			IP:  net.ParseIP("34.246.100.156").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("752038ca7a0359e967d5096453935a5c3d5a13864c3551bd60c5d7d8e6547b2d68b1ceb484d872116ac6977b78d1d39fab8ebd92d22e68b032ffc196fa6cecd7"),
		},
		//eu-p2p-1
		{
			IP:  net.ParseIP("99.81.30.183").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("6c24f4531d755d647ee3d8082f7945f051032c7bc1fc6c90ae6c328092efa2cf1ce429db01e7c4efe26f198eecf996979c2958745ac1f4d831f88231abd0096e"),
		},
		//eu-p2p-2
		{
			IP:  net.ParseIP("34.243.159.16").To4(),
			UDP: 30303,
			TCP: 30303,
			ID:  decodePubkeyV4("f39da1c3b027b5683387c724363e0e132c287a6094564a05b43e8f22508e973098b3c7234df09beabcc19827f1d8998bd1e1d960fb5949bac0317bbe7fcb20a4"),
		},
	}

	flag.Parse()

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	glogger.Vmodule(*vmodule)
	log.Root().SetHandler(glogger)

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

	if *network == "testnet" {
		staticV4Nodes = staticV4NodesTestnet
	} else {
		staticV4Nodes = staticV4NodesMainnet
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

	realaddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, nil, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}

	printNotice(&nodeKey.PublicKey, *realaddr)

	db, _ := enode.OpenDB("")
	ln := enode.NewLocalNode(db, nodeKey)
	cfg := discover.Config{
		PrivateKey:    nodeKey,
		NetRestrict:   restrictList,
		StaticV4Nodes: staticV4Nodes,
	}
	if *runv5 {
		if _, err := discover.ListenV5(conn, ln, cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	} else {
		if _, err := discover.ListenUDP(conn, ln, cfg); err != nil {
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

// decodePubkeyV4
func decodePubkeyV4(hexPubkey string) v4wire.Pubkey {
	pubkeyBytes, err := hex.DecodeString(hexPubkey)
	if err != nil {
		return v4wire.Pubkey{}
	}
	if len(pubkeyBytes) != 64 {
		return v4wire.Pubkey{}
	}

	var pubkey v4wire.Pubkey
	copy(pubkey[:], pubkeyBytes)
	return pubkey
}
