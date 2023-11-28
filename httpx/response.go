package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"

	"github.com/jekjektuanakal/versago/errkind"
)

func WriteResponse[T any](writer http.ResponseWriter, body T, err error) {
	if err != nil {
		WriteError(writer, getStatusCode(err), err)

		return
	}

	kind := reflect.ValueOf(body).Kind()
	value := reflect.ValueOf(body)

	switch kind {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			WriteError(writer, http.StatusNotFound, fmt.Errorf("value is nil: %w", errkind.ErrEmptyValue))
			return
		}
	case reflect.Slice, reflect.Map, reflect.Array:
		if value.Len() == 0 {
			WriteError(writer, http.StatusNotFound, fmt.Errorf("len is 0: %w", errkind.ErrEmptyValue))
			return
		}
	}

	responseJSON, err := json.Marshal(body)
	if err != nil {
		err = fmt.Errorf("failed to marshal response body: %w", errkind.ErrUnknown)
		WriteError(writer, http.StatusInternalServerError, err)

		return
	}

	_, err = writer.Write(responseJSON)
	if err != nil {
		err = fmt.Errorf("failed to write response body: %w", errkind.ErrUnknown)
		WriteError(writer, http.StatusInternalServerError, err)

		return
	}
}

func getStatusCode(err error) int {
	switch {
	case errors.Is(err, errkind.ErrExternalService):
		return http.StatusServiceUnavailable
	case errors.Is(err, errkind.ErrInvalidRequest), errors.Is(err, errkind.ErrInvalidArgument):
		return http.StatusBadRequest
	case errors.Is(err, errkind.ErrInvalidUser),
		errors.Is(err, errkind.ErrUnauthorized),
		errors.Is(err, errkind.ErrInvalidAPIKey):
		return http.StatusUnauthorized
	case errors.Is(err, errkind.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, errkind.ErrNotImplemented):
		return http.StatusNotImplemented
	case errors.Is(err, errkind.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, errkind.ErrConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func WriteError(w http.ResponseWriter, status int, err error) {
	errorCode := strings.ReplaceAll(strings.ToLower(http.StatusText(status)), " ", "_")

	if err == nil {
		err = errors.New("unknown error")
	}

	w.WriteHeader(status)

	body := []byte(fmt.Sprintf(`{"error_code": %q, "message": %q}`, errorCode, err.Error()))

	_, err = w.Write(body)
	if err != nil {
		log.Error().Err(err).Msg("failed to write error response")
	}
}
