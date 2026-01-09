package server

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/Aetherinox/go-virustotal"
)

func (s *Server) virusTotalHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := sanitize(vars["filename"])

	contentLength := r.ContentLength
	contentType := r.Header.Get("Content-Type")

	s.logger.Printf("Submitting to VirusTotal: %s %d %s", filename, contentLength, contentType)

	vt, err := virustotal.NewVirusTotal(s.VirusTotalKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	reader := r.Body

	result, err := vt.Scan(filename, reader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	s.logger.Println(result)
	_, _ = w.Write([]byte(fmt.Sprintf("%v\n", result.Permalink)))
}
