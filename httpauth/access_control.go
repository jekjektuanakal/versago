package httpauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/exp/slices"

	"github.com/jekjektuanakal/versago/errkind"
	"github.com/jekjektuanakal/versago/httpx"
)

type Subject struct {
	DID        string
	Role       string
	Disabled   bool
	Attributes map[string]string
}

type Subjects interface {
	SetSubject(ctx context.Context, subject Subject) error
	GetSubjectByDID(ctx context.Context, did string) (Subject, error)
	GetSubjectsByAttribute(ctx context.Context, attributeKey, attributeValue string) ([]Subject, error)
	DeleteSubjectByDID(ctx context.Context, did string) error
}

type Policy struct {
	Role    string
	Path    string
	Methods []string
}

type Policies interface {
	SetPolicy(ctx context.Context, policy Policy) error
	GetAllPolicies(ctx context.Context) ([]Policy, error)
}

type AccessController struct {
	subjects Subjects
	policies Policies
}

func NewAccessController(subjects Subjects, policies Policies) (*AccessController, error) {
	if subjects == nil || policies == nil {
		return nil, errkind.ErrInvalidArgument
	}

	return &AccessController{
		subjects: subjects,
		policies: policies,
	}, nil
}

func (acl *AccessController) authorizeAccess(request http.Request, subject Subject) error {
	policies, err := acl.policies.GetAllPolicies(request.Context())
	if err != nil {
		return fmt.Errorf("failed to get policies: %w: %w", errkind.ErrInternal, err)
	}

	if len(policies) == 0 {
		return fmt.Errorf("no policy found: %w", errkind.ErrForbidden)
	}

	for i := range policies {
		for param, attr := range subject.Attributes {
			policies[i].Path = strings.ReplaceAll(policies[i].Path, fmt.Sprintf("{%s}", param), attr)
		}
	}

	for _, policy := range policies {
		var pathMatched bool

		pathMatched, err = regexp.Match(policy.Path+".*", []byte(request.URL.Path))
		if err != nil {
			return fmt.Errorf("failed to match path: %w", errkind.ErrInternal)
		}

		if (policy.Role == "" || policy.Role == subject.Role) &&
			slices.Contains(policy.Methods, request.Method) &&
			pathMatched {
			return nil
		}
	}

	return fmt.Errorf("subject is not allowed to access resource: %w", errkind.ErrForbidden)
}

func (acl *AccessController) getSubjectFromRequest(request http.Request) (Subject, error) {
	token, tokenFound := request.Context().Value(CtxKeyJWT).(jwt.Token)
	if !tokenFound {
		return Subject{}, fmt.Errorf("require JWT Authenticator middleware: %w", errkind.ErrInternal)
	}

	subjectDID, subjectDidFound := token.PrivateClaims()["did"].(string)
	if !subjectDidFound || subjectDID == "" {
		return Subject{}, fmt.Errorf("invalid token: %w", errkind.ErrUnauthorized)
	}

	subject, err := acl.subjects.GetSubjectByDID(request.Context(), subjectDID)
	if err != nil && !errors.Is(err, errkind.ErrNotFound) {
		return Subject{}, fmt.Errorf("failed to get subject by DID: %w: %w", errkind.ErrInternal, err)
	}

	if errors.Is(err, errkind.ErrNotFound) {
		subject.DID = subjectDID
	}

	if subject.Disabled {
		subject.Attributes = nil
	}

	if subject.Attributes == nil {
		subject.Attributes = make(map[string]string)
	}

	subject.Attributes["did"] = subject.DID

	return subject, nil
}

func (acl *AccessController) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			subject, err := acl.getSubjectFromRequest(*r)
			if err != nil {
				httpx.WriteResponse(w, struct{}{}, err)
				return
			}

			err = acl.authorizeAccess(*r, subject)
			if err != nil {
				httpx.WriteResponse(w, struct{}{}, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), CtxKeyDIDClaim, subject.DID)))
		})
}
