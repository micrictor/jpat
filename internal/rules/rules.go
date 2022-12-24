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
)

type RulesEngine struct {
	// activeTerms will maintain the state of currently open terms.
	// It is sorted by expiration time at insertion
	activeTerms []Term
}

// Attempt to add a term for a given token and source address.
// Will return errors if the JWT is invalid.
func (r *RulesEngine) TryAddTerm(sourceAddr *net.UDPAddr, token *jwt.Token, appConfig *config.AppConfig) (int64, error) {
	if !token.Valid {
		return 0, errors.New("token is not valid")
	}

	service := appConfig.Service

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("failed to get token claims")
	}
	exp, ok := claims["exp"]
	if !ok {
		return 0, fmt.Errorf("failed to get token exp")
	}

	now := time.Now().Unix()
	expiration := int64(math.Min(float64(now+service.Ttl), exp.(float64)))
	// Once everything is validated, start adding the term in a different thread
	go r.addTerm(Term{
		Comment:         fmt.Sprintf("jpat:%v;exp=%v", sourceAddr.IP, expiration),
		SourceAddr:      sourceAddr.IP,
		DestinationAddr: net.ParseIP(service.Host),
		DestinationPort: service.Port,
		Protocol:        service.Protocol,
		Expiration:      expiration,
	})
	return expiration, nil
}

// Given the input term, apply it and add it to the state.
func (r *RulesEngine) addTerm(term Term) {
	err := r.ApplyTerm(term)
	if err != nil {
		log.Printf("failed to apply term: %v", err)
	}

	if len(r.activeTerms) == 0 {
		r.activeTerms = []Term{term}
	}
	// Iterate backwards through the terms, as new terms are more likely to
	// have later expirations than previous terms
	for i := 0; i < len(r.activeTerms)-1; i = i + 1 {
		trailingIdx := len(r.activeTerms) - 1 - i
		// If we're at the start of the list, then this needs to be the first item
		if trailingIdx == 0 {
			r.activeTerms = append([]Term{term}, r.activeTerms...)
		}
		currentTerm := r.activeTerms[trailingIdx]
		if currentTerm.Expiration > term.Expiration {
			firstHalf := append(r.activeTerms[:trailingIdx], term)
			r.activeTerms = append(firstHalf, r.activeTerms[trailingIdx:]...)
		}
	}
}

func (r *RulesEngine) Init() {
	go r.ExpireTerms()
}

func (r *RulesEngine) Close() {
	log.Printf("Deleting %d terms at shutdown...", len(r.activeTerms))
	for _, term := range r.activeTerms {
		r.DeleteTerm(term)
	}
}

// Delete terms that have expired. Designed to run as a goroutine.
// Loop indefititely with a 1-second pause between loops.
func (r *RulesEngine) ExpireTerms() {
	for {
		currentTime := time.Now().Unix()
		lastIdx := 0
		for i, term := range r.activeTerms {
			if currentTime < term.Expiration {
				r.activeTerms = r.activeTerms[lastIdx:]
				break
			}
			r.DeleteTerm(term)
			lastIdx = i
		}
		time.Sleep(time.Second)
	}
}

func New() *RulesEngine {
	return &RulesEngine{}
}
