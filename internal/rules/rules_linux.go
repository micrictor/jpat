//go:build linux

package rules

import (
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

const DEFAULT_TABLE = "filter"
const DEFAULT_CHAIN = "INPUT"
const DEFAULT_ACTION = "ACCEPT"
const DEFAULT_PROTOCOL = "tcp"

func Close() {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Panicf("failed to open iptables for close: %v", err)
	}
	log.Printf("Cleaning up %d exisiting IPTables rule(s)", len(activeRules))

	for _, r := range activeRules {
		ruleSpec := convertRule(r)
		err = ipt.DeleteIfExists(DEFAULT_TABLE, DEFAULT_CHAIN, ruleSpec...)
		if err != nil {
			log.Printf("failed to delete rule: %v", err)
		}
	}
}

func ApplyRule(rule Rule) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("failed to open iptables: %v", err)
	}

	log.Printf("%v", rule.Destination)
	ruleSpec := convertRule(rule)
	err = ipt.AppendUnique(DEFAULT_TABLE, DEFAULT_CHAIN, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to add rule: %v", err)
	}
	activeRules = append(activeRules, rule)
	go scheduleRuleDeletion(rule)
	return nil
}

// Convert internal rule struct into the proper rule spec for IPTables
func convertRule(rule Rule) []string {
	return []string{
		"--protocol",
		DEFAULT_PROTOCOL,
		"--source",
		rule.Source.IP.String(),
		"--destination",
		rule.Destination.IP.String(),
		"--dport",
		fmt.Sprintf("%d", rule.Destination.Port),
	}
}

// This is ran as a goroutine, sleeping for the time delta between the current time and the
// expiration time before deleting the rule from the IPTable.
// This won't scale up well - having N goroutines for N active rules is a lot of overhead.
// Would likely best be some sort of async worker, either a goroutine or a dedicated thread,
// with a shared context of the list of active rules to check for expiration at a desired
// resolution - once every 30 seconds, once per minute, etc
func scheduleRuleDeletion(rule Rule) {
	timeDelay := rule.Expiration - uint64(time.Now().Unix())
	time.Sleep(time.Duration(timeDelay * 10e8))
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Panicf("failed to open iptables for close: %v", err)
	}
	log.Printf("Deleting rule %v as it has expired.", rule)

	ruleSpec := convertRule(rule)
	err = ipt.DeleteIfExists(DEFAULT_TABLE, DEFAULT_CHAIN, ruleSpec...)
	if err != nil {
		log.Printf("failed to delete rule: %v", err)
	}
}
