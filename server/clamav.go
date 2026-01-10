package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/gorilla/mux"
)

const clamavScanStatusOK = "OK"

func (s *Server) scanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := sanitize(vars["filename"])

	contentLength := r.ContentLength
	contentType := r.Header.Get("Content-Type")

	s.logger.Printf("Scanning %s %d %s", filename, contentLength, contentType)

	file, err := os.CreateTemp(s.tempPath, "clamav-")
	defer s.cleanTmpFile(file)
	if err != nil {
		s.logger.Printf("clamav: failed to create temp file: %v", err)
		http.Error(w, "Could not process scan.", http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(file, r.Body)
	if err != nil {
		s.logger.Printf("clamav: failed to copy file: %v", err)
		http.Error(w, "Could not process scan.", http.StatusInternalServerError)
		return
	}

	status, err := s.performScan(file.Name())
	if err != nil {
		s.logger.Printf("clamav: scan failed: %v", err)
		http.Error(w, "Could not scan file.", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(fmt.Sprintf("%v\n", status)))
}

func (s *Server) performScan(path string) (string, error) {
	c := clamd.NewClamd(s.ClamAVDaemonHost)

	responseCh := make(chan chan *clamd.ScanResult, 1)
	errCh := make(chan error, 1)
	go func(responseCh chan chan *clamd.ScanResult, errCh chan error) {
		response, err := c.ScanFile(path)
		if err != nil {
			errCh <- err
			return
		}

		responseCh <- response
	}(responseCh, errCh)

	select {
	case err := <-errCh:
		return "", err
	case response := <-responseCh:
		st := <-response
		return st.Status, nil
	case <-time.After(time.Second * 60):
		return "", errors.New("clamav scan timeout")
	}
}
