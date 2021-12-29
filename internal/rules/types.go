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

var activeRules []Rule
