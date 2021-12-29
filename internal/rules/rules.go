package rules

import (
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/micrictor/jpat/internal/config"
)

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
