//go:build linux

package rules

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

const DEFAULT_TABLE = "filter"
const DEFAULT_CHAIN = "INPUT"
const DEFAULT_ACTION = "ACCEPT"
const DEFAULT_PROTOCOL = "tcp"

var IPTV4 *iptables.IPTables
var IPTV6 *iptables.IPTables

func (r *RulesEngine) ApplyTerm(term Term) error {
	ipt, err := getOrCreateIpt(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("failed to open iptables: %v", err)
	}

	ruleSpec := convertTerm(term)
	err = ipt.AppendUnique(DEFAULT_TABLE, DEFAULT_CHAIN, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to add rule: %v", err)
	}
	return nil
}

func (r *RulesEngine) DeleteTerm(term Term) error {
	ipt, err := getOrCreateIpt(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("failed to open iptables for delete: %v", err)
	}

	ruleSpec := convertTerm(term)
	err = ipt.DeleteIfExists(DEFAULT_TABLE, DEFAULT_CHAIN, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to delete term %v", err)
	}
	return nil
}

// Convert internal term struct into the proper rule spec for IPTables
func convertTerm(term Term) []string {
	return []string{
		"--protocol",
		term.Protocol,
		"--source",
		term.SourceAddr.String(),
		"--destination",
		term.DestinationAddr.String(),
		"--dport",
		fmt.Sprintf("%d", term.DestinationPort),
	}
}

func getOrCreateIpt(protocol iptables.Protocol) (*iptables.IPTables, error) {
	switch protocol {
	case iptables.ProtocolIPv4:
		if IPTV4 != nil {
			return IPTV4, nil
		}
		ipt, err := iptables.NewWithProtocol(protocol)
		if err == nil {
			IPTV4 = ipt
		}
		return ipt, err
	case iptables.ProtocolIPv6:
		if IPTV6 != nil {
			return IPTV6, nil
		}
		ipt, err := iptables.NewWithProtocol(protocol)
		if err == nil {
			IPTV6 = ipt
		}
		return ipt, err
	default:
		return nil, fmt.Errorf("invalid protocol: %v", protocol)
	}
}
