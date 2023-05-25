package celeritas

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
)

type APIResponse struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

func (c *Celeritas) ReadJSON(w http.ResponseWriter, r *http.Request, data interface{}) error {
	maxBytes := 1048576 // one megabyte
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(data)
	if err != nil {
		return err
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return errors.New("body must only have a single json value")
	}

	return nil
}

func (c *Celeritas) WriteJSON(w http.ResponseWriter, status int, data interface{}, headers ...http.Header) error {
	out, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	if len(headers) > 0 {
		for key, value := range headers[0] {
			w.Header()[key] = value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func (c *Celeritas) WriteDataResponse(w http.ResponseWriter, status int, message string, data interface{}, headers ...http.Header) error {
	return c.WriteJSON(w, status, &APIResponse{
		Message: message,
		Data:    data,
	}, headers...)
}

func (c *Celeritas) WriteErrorResponse(w http.ResponseWriter, status int, err error, headers ...http.Header) error {
	return c.WriteJSON(w, status, &APIResponse{
		Error: err.Error(),
	}, headers...)
}

func (c *Celeritas) WriteErrorResponseWithData(w http.ResponseWriter, status int, err error, data interface{}, headers ...http.Header) error {
	return c.WriteJSON(w, status, &APIResponse{
		Error: err.Error(),
		Data:  data,
	}, headers...)
}

func (c *Celeritas) WriteSuccessResponse(w http.ResponseWriter, status int, message string, headers ...http.Header) error {
	return c.WriteJSON(w, status, &APIResponse{
		Message: message,
	}, headers...)
}

// DownloadFile downloads a file
func (c *Celeritas) DownloadFile(w http.ResponseWriter, r *http.Request, pathToFile, fileName string) error {
	fp := path.Join(pathToFile, fileName)
	fileToServe := filepath.Clean(fp)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; file=\"%s\"", fileName))
	http.ServeFile(w, r, fileToServe)
	return nil
}
