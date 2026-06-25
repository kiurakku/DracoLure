package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
)

var dbConn *sql.DB

type LogEntry struct {
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
	RequestPath string `json:"request_path"`
}

func logRequest(w http.ResponseWriter, r *http.Request) {
	entry := LogEntry{
		IP:          r.RemoteAddr,
		UserAgent:   r.UserAgent(),
		RequestPath: r.URL.Path,
	}

	if dbConn != nil {
		_, err := dbConn.Exec(
			"INSERT INTO logs (ip, user_agent, request_path) VALUES ($1, $2, $3)",
			entry.IP, entry.UserAgent, entry.RequestPath,
		)
		if err != nil {
			log.Printf("failed to persist log entry: %v", err)
		}
	}

	log.Printf("Received request: %+v", entry)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Logged"})
}
