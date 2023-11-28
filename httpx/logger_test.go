package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		// response ok, error, or panic based on query param

		// parse query param
		status, _ := strconv.Atoi(r.URL.Query().Get("status"))
		// if error, write error
		if status < 400 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("{}"))

			return
		}

		if status < 500 {
			WriteError(w, status, errors.New("request failed"))

			return
		}

		if status == 503 {
			WriteError(w, status, errors.New("service unavailable"))

			return
		}

		if status == 500 {
			panic("request panicked")
		}
	})

	handler := LogErrorWithRecover(mux)

	t.Run("status 200, doesn't log", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/hello?status=200", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, 200, w.Code)
	})

	t.Run("status 400, logs warning with response body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/hello?status=400", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, 400, w.Code)
	})

	t.Run("status 503, logs error with response body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/hello?status=503", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, 503, w.Code)
	})

	t.Run("status 500, logs error with stack trace", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/hello?status=500", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, 500, w.Code)
	})
}
