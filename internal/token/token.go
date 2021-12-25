package token

import (
	config "github.com/micrictor/jpat/internal/config"

	jwt "github.com/golang-jwt/jwt"
)

func ProcessToken(token string, configuration *config.AppConfig) (*jwt.Token, error) {
	resultToken, err := jwt.Parse(token, configuration.Keyfunc)
	if err != nil {
		return nil, err
	}

	return resultToken, err
}
