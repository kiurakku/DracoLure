package main

import (
	"log"
	"net/http"
)

func main() {
	var err error
	dbConn, err = connectDB()
	if err != nil {
		log.Printf("database unavailable, logging to stdout only: %v", err)
	}

	http.HandleFunc("/log", logRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":8080"
	log.Printf("Go service listening on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
