package token

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mkw.re/ghidra-panel/common"
)

// TODO Integrate BitRing for token expiry

const jwtValidity = 90 * 24 * time.Hour

type Issuer struct {
	Secret []byte
}

func NewIssuer(secret []byte) Issuer {
	return Issuer{secret}
}

type Claims struct {
	jwt.RegisteredClaims
	Name       string `json:"name,omitempty"`
	AvatarHash string `json:"avatar,omitempty"`
}

func (iss Issuer) Issue(ident *common.Identity) (string, time.Time) {
	iat := time.Now()
	exp := iat.Add(jwtValidity)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatUint(ident.ID, 10),
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Name:       ident.Username,
		AvatarHash: ident.AvatarHash,
	})

	tokenString, err := token.SignedString(iss.Secret)
	if err != nil {
		log.Panicf("jwt signing failed: %v", err)
	}
	return tokenString, exp
}

func (iss Issuer) Verify(tokenString string) (ident *common.Identity, err error) {
	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return iss.Secret, nil
	})
	if err != nil {
		return nil, err
	}

	// Parse claims
	claims := token.Claims.(*Claims)
	id, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject: %v", err)
	}

	// Reconstruct identity
	return &common.Identity{
		ID:         id,
		Username:   claims.Name,
		AvatarHash: claims.AvatarHash,
	}, nil
}
