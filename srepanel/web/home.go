package web

import (
	"log"
	"net/http"
)

func (s *Server) handleHome(wr http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(wr, req)
		return
	}

	state := s.stateWithNav(req, Nav{Route: "/", Name: "Ghidra"})
	if !s.authenticateState(wr, req, state) {
		return
	}

	err := homePage.Execute(wr, state)
	if err != nil {
		log.Print("failed to serve home: ", err)
	}
}
