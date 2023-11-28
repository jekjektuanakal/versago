package httpauth_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/jekjektuanakal/versago/errkind"
	"github.com/jekjektuanakal/versago/httpauth"
)

type mockSubjects struct {
	values map[string]httpauth.Subject
}

func (m *mockSubjects) SetSubject(_ context.Context, subject httpauth.Subject) error {
	m.values[subject.DID] = subject

	return nil
}

func (m *mockSubjects) GetSubjectsByAttribute(_ context.Context, attr, value string) ([]httpauth.Subject, error) {
	var subjects []httpauth.Subject

	for _, subject := range m.values {
		if subject.Attributes[attr] == value {
			subjects = append(subjects, subject)
		}
	}

	return subjects, nil
}

func (m *mockSubjects) GetSubjectByDID(_ context.Context, did string) (httpauth.Subject, error) {
	if !strings.HasPrefix(did, "did:ethr") {
		return httpauth.Subject{}, errkind.ErrInvalidRequest
	}

	subject, ok := m.values[did]

	if !ok {
		return httpauth.Subject{}, errkind.ErrNotFound
	}

	return subject, nil
}

func (m *mockSubjects) DeleteSubjectByDID(_ context.Context, did string) error {
	delete(m.values, did)

	return nil
}

type mockPolicies struct {
	values []httpauth.Policy
}

func (m *mockPolicies) SetPolicy(_ context.Context, policy httpauth.Policy) error {
	for i, p := range m.values {
		if p.Role == policy.Role && p.Path == policy.Path {
			m.values[i] = policy
			return nil
		}
	}

	return nil
}

func (m *mockPolicies) GetAllPolicies(_ context.Context) ([]httpauth.Policy, error) {
	return m.values, nil
}

type HTTPAuthTestSuite struct {
	suite.Suite
	router           *chi.Mux
	subjects         *mockSubjects
	policies         *mockPolicies
	accessController *httpauth.AccessController
	jwtAuthenticator *httpauth.JWTAuthenticator
}

func TestHttpAuthTestSuite(t *testing.T) {
	suite.Run(t, new(HTTPAuthTestSuite))
}

func (s *HTTPAuthTestSuite) SetupSuite() {
	s.subjects = &mockSubjects{values: map[string]httpauth.Subject{}}
	s.policies = &mockPolicies{values: []httpauth.Policy{}}

	s.accessController, _ = httpauth.NewAccessController(s.subjects, s.policies)

	go runJWKSServer()

	time.Sleep(1 * time.Second)

	jwksURL, _ := url.Parse("http://localhost:7999/jwks")
	s.jwtAuthenticator, _ = httpauth.NewJWTAuthenticatorFromJWKSURL(*jwksURL, 10*time.Second)

	s.router = chi.NewRouter()
	s.router.Route("/noauthz", func(router chi.Router) {
		router.Use(s.jwtAuthenticator.Authenticate)

		router.Get("/{param}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})
	})
	s.router.Route("/noauthn", func(router chi.Router) {
		router.Use(s.accessController.Authorize)

		router.Get("/{param}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})
	})
	s.router.Route("/", func(router chi.Router) {
		router.Use(s.jwtAuthenticator.Authenticate)
		router.Use(s.accessController.Authorize)

		router.Get("/user/{param}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.Get("/user/{param}/profile", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.Get("/public/{param}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})
	})
}

func (s *HTTPAuthTestSuite) TestNewAccessController() {
	s.Run("subjects and policies are nil, should return error", func() {
		_, err := httpauth.NewAccessController(nil, nil)

		s.ErrorIs(err, errkind.ErrInvalidArgument)
	})

	s.Run("subjects is nil, should return error", func() {
		_, err := httpauth.NewAccessController(nil, &mockPolicies{})

		s.ErrorIs(err, errkind.ErrInvalidArgument)
	})

	s.Run("policies is nil, should return error", func() {
		_, err := httpauth.NewAccessController(&mockSubjects{}, nil)

		s.ErrorIs(err, errkind.ErrInvalidArgument)
	})

	s.Run("subjects and policies are not nil, should return AccessController", func() {
		_, err := httpauth.NewAccessController(&mockSubjects{}, &mockPolicies{})

		s.NoError(err)
	})
}

func (s *HTTPAuthTestSuite) TestAuthenticateJWT() {
	s.Run("no Authorization header, should return unauthorized", func() {
		req := httptest.NewRequest(http.MethodGet, "/noauthz/123", nil)
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusUnauthorized, writer.Code)
	})

	s.Run("invalid Authorization header, should return unauthorized", func() {
		req := httptest.NewRequest(http.MethodGet, "/noauthz/123", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusUnauthorized, writer.Code)
	})

	s.Run("valid Authorization header, should return ok", func() {
		req := httptest.NewRequest(http.MethodGet, "/noauthz/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})
}

func (s *HTTPAuthTestSuite) TestAuthorizeJWT() {
	s.Run("no Authenticate middleware, should be forbidden", func() {
		req := httptest.NewRequest(http.MethodGet, "/noauthn/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x5678"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusInternalServerError, writer.Code)
	})

	s.Run("policy is not found, should be forbidden", func() {
		req := httptest.NewRequest(http.MethodGet, "/public/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x5678"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("policy exists and no path match, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/public/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x5678"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("policy is found but subject is not found, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("policy with empty role is found and subject is not found, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy role is empty and subject with any role is found, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "guest",
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy and subject are found but role don't match, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "guest",
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("role match but method don't match, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user",
				Methods: []string{
					http.MethodPost,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "user",
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("role and method match, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "user",
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		assert.Equal(s.T(), http.StatusOK, writer.Code)
	})

	s.Run("policy param doesn't match request, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user/{param}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "user",
			Attributes: map[string]string{
				"param": "456",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("policy param matches request, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user/{param}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:  "did:ethr:0x1234",
			Role: "user",
			Attributes: map[string]string{
				"param": "123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy role is empty and param matches request, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Path: "/user/{param}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			Role: "guest",
			DID:  "did:ethr:0x1234",
			Attributes: map[string]string{
				"param": "123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("subject is not found and policy role is empty and it has did param, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Path: "/user/{did}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values = map[string]httpauth.Subject{}

		req := httptest.NewRequest(http.MethodGet, "/user/did:ethr:0x1234", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy param matches request but subject is disabled, should be forbidden", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user/{param}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:      "did:ethr:0x1234",
			Role:     "user",
			Disabled: true,
			Attributes: map[string]string{
				"param": "123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusForbidden, writer.Code)
	})

	s.Run("policy param 'did' matches request but subject is disabled, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "user",
				Path: "/user/{did}",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:      "did:ethr:0x1234",
			Role:     "user",
			Disabled: true,
			Attributes: map[string]string{
				"param": "123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/did:ethr:0x1234", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy param regex matches request and subject is not found, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "",
				Path: "/user/[^/]+/profile",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values = map[string]httpauth.Subject{}

		req := httptest.NewRequest(http.MethodGet, "/user/123/profile", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})

	s.Run("policy param regex matches request and subject is disabled, should be ok", func() {
		s.policies.values = []httpauth.Policy{
			{
				Role: "",
				Path: "/user/[^/]+/profile",
				Methods: []string{
					http.MethodGet,
				},
			},
		}
		s.subjects.values["did:ethr:0x1234"] = httpauth.Subject{
			DID:      "did:ethr:0x1234",
			Role:     "user",
			Disabled: true,
			Attributes: map[string]string{
				"param": "123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/user/123/profile", nil)
		req.Header.Set("Authorization", newAuthHeader("did:ethr:0x1234"))
		writer := httptest.NewRecorder()

		s.router.ServeHTTP(writer, req)

		s.Equal(http.StatusOK, writer.Code)
	})
}

func runJWKSServer() {
	func() {
		const rawJwks = `{
			"keys": [
				{
					"kid": "kuncipas",
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"x": "eWh58clljguPun13lJn2CtHjOpCKaQpKq1m9JtH-xF4",
					"y": "5Z5V3kP9Oh8vBNE_GEZmQHssy_MXfw_VSnBO4bAtF1Y",
					"alg": "ES256"
				}
			]
		}`

		http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, rawJwks)
		})

		log.Info().Msg("starting JWKS server on port 7999")
		log.Fatal().Err(http.ListenAndServe(":7999", nil))
	}()
}

func newAuthHeader(subject string) string {
	const rawPrivateJwk = `{
		"kid": "kuncipas",
		"kty": "EC",
		"d": "YJLYpEd5idlp9SGqgR0yZy6oKuU2NEqiGIJ3C5HA31Y",
		"use": "sig",
		"crv": "P-256",
		"x": "eWh58clljguPun13lJn2CtHjOpCKaQpKq1m9JtH-xF4",
		"y": "5Z5V3kP9Oh8vBNE_GEZmQHssy_MXfw_VSnBO4bAtF1Y",
		"alg": "ES256"
	}`

	privateKey, _ := jwk.ParseKey([]byte(rawPrivateJwk))

	token := jwt.New()
	_ = token.Set("sub", base64.StdEncoding.EncodeToString([]byte(subject)))
	_ = token.Set("did", subject)

	accessToken, _ := jwt.Sign(token, jwa.ES256, privateKey)

	return "Bearer " + string(accessToken)
}
