package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/log", logRequest)

	addr := ":8080"
	log.Printf("Go service listening on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
