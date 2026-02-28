package main

import "os"

type Config struct {
	Port          string
	CassandraHost string
	CassandraPort string
}

func LoadConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	host := os.Getenv("CASSANDRA_HOST")
	if host == "" {
		host = "cassandra"
	}

	cport := os.Getenv("CASSANDRA_PORT")
	if cport == "" {
		cport = "9042"
	}

	return Config{
		Port:          port,
		CassandraHost: host,
		CassandraPort: cport,
	}
}
