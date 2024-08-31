package main

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/otakakot/sample-go-s2s/pkg/api"
	"github.com/otakakot/sample-go-s2s/pkg/schema"
)

func main() {
	port := cmp.Or(os.Getenv("PORT"), "8080")

	dsn := cmp.Or(os.Getenv("DSN"), "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	conn, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		panic(err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), conn)
	if err != nil {
		panic(err)
	}

	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	hdl := api.HandlerWithOptions(&Hander{
		queries: schema.New(pool),
	}, api.StdHTTPServerOptions{
		BaseRouter: mux,
		Middlewares: []api.MiddlewareFunc{
			func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					slog.InfoContext(r.Context(), r.Method+" "+r.URL.Path+" start")
					defer slog.InfoContext(r.Context(), r.Method+" "+r.URL.Path+" end")

					h.ServeHTTP(w, r)
				})
			},
		},
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}

var _ api.ServerInterface = (*Hander)(nil)

type Hander struct {
	queries *schema.Queries
}

// GetCerts implements api.ServerInterface.
func (hdl *Hander) GetCerts(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("GetCerts"))
}

// PostCerts implements api.ServerInterface.
func (hdl *Hander) PostCerts(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	jwkSetKey := api.JWKSetKey{}

	if err := json.NewDecoder(r.Body).Decode(&jwkSetKey); err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	nbytes, err := base64.RawURLEncoding.DecodeString(jwkSetKey.N)
	if err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	n := new(big.Int).SetBytes(nbytes)

	ebytes, err := base64.RawURLEncoding.DecodeString(jwkSetKey.E)
	if err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	e := new(big.Int).SetBytes(ebytes)

	pubkey := rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	der, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	if _, err := hdl.queries.CreateCert(r.Context(), schema.CreateCertParams{
		ID:  jwkSetKey.Kid,
		Der: der,
	}); err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	res := api.JWKSetKey{
		Kid: jwkSetKey.Kid,
		N:   jwkSetKey.N,
		E:   jwkSetKey.E,
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
}

// Verify implements api.ServerInterface.
func (hdl *Hander) Verify(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		slog.WarnContext(r.Context(), "Authorization header is required")

		http.Error(w, "Authorization header is required", http.StatusUnauthorized)

		return
	}

	tokenString := strings.TrimPrefix(authorization, "Bearer ")
	if tokenString == authorization {
		slog.WarnContext(r.Context(), "invalid Authorization header format")

		http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)

		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("find kid")
		}

		cert, err := hdl.queries.FindCertByID(r.Context(), uuid.Must(uuid.Parse(kid)))
		if err != nil {
			return nil, fmt.Errorf("find cert: %w", err)
		}

		pubkey, err := x509.ParsePKIXPublicKey(cert.Der)
		if err != nil {
			return nil, fmt.Errorf("parse pkix public key: %w", err)
		}

		return pubkey, nil
	})
	if err != nil {
		slog.ErrorContext(r.Context(), err.Error())

		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}

	if !token.Valid {
		slog.WarnContext(r.Context(), "token is invalid")

		http.Error(w, "token is invalid", http.StatusUnauthorized)

		return
	}
}
