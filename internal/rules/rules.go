package rules

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/micrictor/jpat/internal/config"

	"github.com/coreos/go-iptables/iptables"
)

type Socket struct {
	IP   net.IP
	Port uint16
}

type Rule struct {
	Source      Socket
	Destination Socket
	Expiration  uint64
}

const DEFAULT_TABLE = "filter"
const DEFAULT_CHAIN = "INPUT"
const DEFAULT_ACTION = "ACCEPT"
const DEFAULT_PROTOCOL = "tcp"

var activeRules []Rule

func GetRule(sourceAddr *net.UDPAddr, token *jwt.Token, appConfig *config.AppConfig) (Rule, error) {
	if !token.Valid {
		return Rule{}, errors.New("token is not valid")
	}

	service := appConfig.Service
	if service.Host == "" || service.Port == 0 || service.Ttl == 0 {
		return Rule{}, fmt.Errorf("invalid service definition %v", service)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Rule{}, fmt.Errorf("failed to get token claims")
	}
	exp, ok := claims["exp"]
	if !ok {
		return Rule{}, fmt.Errorf("failed to get token exp")
	}

	now := time.Now().Unix()
	expiration := uint64(math.Min(float64(now+service.Ttl), exp.(float64)))

	return Rule{
		Source: Socket{
			IP:   sourceAddr.IP,
			Port: uint16(sourceAddr.Port),
		},
		Destination: Socket{
			IP:   net.ParseIP(service.Host),
			Port: service.Port,
		},
		Expiration: expiration,
	}, nil
}

func Close() {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Panicf("failed to open iptables for close: %v", err)
	}
	log.Printf("Cleaning up %d exisiting IPTables rules", len(activeRules))

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
