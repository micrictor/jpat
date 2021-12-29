//go:build windows

package rules

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
	"inet.af/wf"
)

func Close() {

}

func ApplyRule(rule Rule) error {
	session, err := wf.New(&wf.Options{
		Name:        "jpat",
		Description: "JPAT SPA",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("creating wf session: %v", err)
	}

	rules, _ := session.Rules()

	for _, r := range rules {
		if r.Name == "ACANARYNAME" {
			log.Printf("%v", r)
		}
	}

	wfRule := convertRule(rule)

	if err := session.AddRule(&wfRule); err != nil {
		return err
	}
	go scheduleRuleDeletion(rule, wfRule.ID)
	return nil
}

func convertRule(rule Rule) wf.Rule {
	ruleGuid, err := windows.GenerateGUID()
	if err != nil {
		log.Printf("Failed to create GUID for new rule: %v", err)
		return wf.Rule{}
	}

	convertedSource, _ := netaddr.FromStdIP(rule.Source.IP)
	sublayer, _ := windows.GUIDFromString("{B3CDD441-AF90-41BA-A745-7C6008FF2301}")

	return wf.Rule{
		ID:          wf.RuleID(ruleGuid),
		KernelID:    4,
		Name:        fmt.Sprintf("JPAT Rule for %s", rule.Source.IP.String()),
		Description: fmt.Sprintf("JPAT Rule for %s", rule.Source.IP.String()),
		Layer:       wf.LayerALEAuthRecvAcceptV4,
		Sublayer:    wf.SublayerID(sublayer),
		Weight:      1,
		Action:      wf.ActionPermit,
		Conditions: []*wf.Match{
			&wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: convertedSource,
			},
			&wf.Match{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: rule.Destination.Port,
			},
		},
	}
}

// This is ran as a goroutine, sleeping for the time delta between the current time and the
// expiration time before deleting the rule from the IPTable.
// This won't scale up well - having N goroutines for N active rules is a lot of overhead.
// Would likely best be some sort of async worker, either a goroutine or a dedicated thread,
// with a shared context of the list of active rules to check for expiration at a desired
// resolution - once every 30 seconds, once per minute, etc
func scheduleRuleDeletion(rule Rule, wfpRuleId wf.RuleID) {
	timeDelay := rule.Expiration - uint64(time.Now().Unix())
	time.Sleep(time.Duration(timeDelay * 10e8))

	session, err := wf.New(&wf.Options{
		Name:        "jpat",
		Description: "JPAT SPA",
		Dynamic:     true,
	})
	if err != nil {
		log.Printf("error creating wf session for rule deletion: %v", err)
	}

	log.Printf("Deleting rule %v as it has expired.", rule)
	if err := session.DeleteRule(wfpRuleId); err != nil {
		log.Printf("error deleting rule: %v", err)
	}
}
