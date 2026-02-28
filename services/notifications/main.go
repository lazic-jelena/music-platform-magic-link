package main

import (
	"log"
	"net/http"
)

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For demo purposes allow all origins
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg := LoadConfig()

	repo, err := NewNotificationRepository(cfg)
	if err != nil {
		log.Fatal(err)
	}

	handler := NewNotificationHandler(repo)

	mux := http.NewServeMux()
	mux.HandleFunc("/notifications", handler.GetNotifications)

	log.Println("Notifications service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", withCORS(mux)))
}
