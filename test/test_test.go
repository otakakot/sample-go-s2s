package test_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/otakakot/sample-go-s2s/pkg/api"
)

func TestXxx(t *testing.T) {
	key := GenerateSignKey(t)

	jwtSetKey := api.JWKSetKey{
		Kid: uuid.New(),
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	buf := bytes.NewBuffer([]byte{})

	if err := json.NewEncoder(buf).Encode(jwtSetKey); err != nil {
		t.Fatalf("json.NewEncoder().Encode() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/certs", buf)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.DefaultClient.Do() error = %v", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("res.StatusCode = %v", res.StatusCode)
	}

	result := api.JWKSetKey{}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatalf("json.NewDecoder().Decode() error = %v", err)
	}

	if result.Kid != jwtSetKey.Kid {
		t.Fatalf("result.Kid = %v, want %v", result.Kid, jwtSetKey.Kid)
	}

	if result.N != jwtSetKey.N {
		t.Fatalf("result.N = %v, want %v", result.N, jwtSetKey.N)
	}

	if result.E != jwtSetKey.E {
		t.Fatalf("result.E = %v, want %v", result.E, jwtSetKey.E)
	}

	vReq, err := http.NewRequest(http.MethodGet, "http://localhost:8080/verify", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	vReq.Header.Set("Authorization", "Bearer "+GenerateJWT(t, key, jwtSetKey.Kid.String()))

	vRes, err := http.DefaultClient.Do(vReq)
	if err != nil {
		t.Fatalf("http.DefaultClient.Do() error = %v", err)
	}

	defer vRes.Body.Close()

	if vRes.StatusCode != http.StatusOK {
		t.Fatalf("vRes.StatusCode = %v", vRes.StatusCode)
	}
}

func GenerateSignKey(
	t *testing.T,
) *rsa.PrivateKey {
	reader := rand.Reader

	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	return key
}

func GenerateJWT(
	t *testing.T,
	key *rsa.PrivateKey,
	kid string,
) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "http://example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	token.Header["kid"] = kid

	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("token.SignedString() error = %v", err)
	}

	return tokenString
}
