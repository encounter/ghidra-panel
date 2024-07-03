package web

import (
	"log"
	"net/http"
)

type ErrorState struct {
	*State
	Message string
}

func (s *Server) renderError(wr http.ResponseWriter, status int, message string, state *State) {
	wr.WriteHeader(status)
	estate := ErrorState{State: state, Message: message}
	if err := errorPage.Execute(wr, estate); err != nil {
		log.Print("Failed to render error page:", err)
		_, _ = wr.Write([]byte("Failed to render the error page"))
	}
}
