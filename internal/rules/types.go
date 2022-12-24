package rules

import "net"

type Socket struct {
	IP   net.IP
	Port uint16
}

type Rule struct {
	Source      Socket
	Destination Socket
	Expiration  uint64
}

type Term struct {
	Comment         string
	SourceAddr      net.IP
	SourcePort      uint16
	DestinationAddr net.IP
	DestinationPort uint16
	Protocol        string
	Expiration      int64
}

type Policy struct {
	Platform string
	Comment  string
	Terms    []Term
}
