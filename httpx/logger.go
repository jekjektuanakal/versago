package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func LogErrorWithRecover(next http.Handler) http.Handler {
	return chi.Chain(
		middleware.RequestID,
		logHTTPErrorWithRecover,
	).Handler(next)
}

func logHTTPErrorWithRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapResponse := middleware.NewWrapResponseWriter(w, 1)
		responseBuffer := newLimitBuffer(512)
		var message []byte
		wrapResponse.Tee(responseBuffer)
		start := time.Now()

		defer func() {
			if rvr := recover(); rvr != nil {
				WriteError(wrapResponse, http.StatusInternalServerError, errors.New("unexpected error"))
				message = getMessageFromRecover(rvr)
			}

			level := getLevelFromHTTPStatus(wrapResponse.Status())
			if level == zerolog.NoLevel {
				return
			}

			var err error
			if message == nil {
				message, err = io.ReadAll(responseBuffer)
				if err != nil {
					message = []byte(strconv.Quote(err.Error()))
				}
			}

			if err = json.Unmarshal(message, &json.RawMessage{}); err != nil {
				message = []byte(strconv.Quote(string(message)))
			}

			log.WithLevel(level).
				Int("status", wrapResponse.Status()).
				Str("req_id", r.Context().Value(middleware.RequestIDKey).(string)).
				Str("path", r.Method+" "+r.URL.String()).
				Int64("elapsed_ms", time.Since(start).Milliseconds()).
				RawJSON("message", message).
				Send()
		}()

		next.ServeHTTP(wrapResponse, r)
	})
}

func getMessageFromRecover(rvr any) []byte {
	recoverError, ok := rvr.(error)
	if ok && errors.Is(recoverError, http.ErrAbortHandler) {
		// we don't recover http.ErrAbortHandler so the response
		// to the client is aborted, this should not be logged
		panic(rvr)
	}

	return []byte(strconv.Quote(string(debug.Stack())))
}

func getLevelFromHTTPStatus(httpStatus int) zerolog.Level {
	switch {
	case httpStatus < 400:
		return zerolog.NoLevel
	case httpStatus < 500:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}

// limitBuffer is used to pipe response body information from the
// response writer to a certain limit amount. The idea is to read
// a portion of the response body such as an error response so we
// may log it.
type limitBuffer struct {
	*bytes.Buffer
	limit int
}

func newLimitBuffer(size int) io.ReadWriter {
	return limitBuffer{
		Buffer: bytes.NewBuffer(make([]byte, 0, size)),
		limit:  size,
	}
}

func (b limitBuffer) Write(p []byte) (n int, err error) {
	if b.Buffer.Len() >= b.limit {
		return len(p), nil
	}

	limit := b.limit

	if len(p) < limit {
		limit = len(p)
	}

	return b.Buffer.Write(p[:limit])
}

func (b limitBuffer) Read(p []byte) (n int, err error) {
	return b.Buffer.Read(p)
}
