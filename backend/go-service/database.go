package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func connectDB() (*sql.DB, error) {
	host := getenv("POSTGRES_HOST", "db")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "honeypot")
	password := getenv("POSTGRES_PASSWORD", "honeypot_secret")
	dbname := getenv("POSTGRES_DB", "honeypot")

	psqlInfo := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	log.Println("Go service connected to database")
	return db, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
