// services/api-gateway/main.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// ===== Minimal DTOs used by composition endpoints =====

type PageResponse[T any] struct {
	Items []T `json:"items"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Total int `json:"total"`
}

type Artist struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Bio       string   `json:"bio"`
	Genres    []string `json:"genres"`
	CreatedAt any      `json:"created_at"`
	UpdatedAt any      `json:"updated_at"`
}

type Album struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Genre       string `json:"genre"`
	ArtistID    string `json:"artist_id"`
	ArtistIDs   any    `json:"artist_ids"`
	ReleaseYear int    `json:"release_year"`
	CreatedAt   any    `json:"created_at"`
	UpdatedAt   any    `json:"updated_at"`
}

type Song struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Genre     string `json:"genre"`
	AlbumID   string `json:"album_id"`
	ArtistID  string `json:"artist_id"`
	ArtistIDs any    `json:"artist_ids"`
	Duration  int    `json:"duration"`
	TrackNum  int    `json:"track_number"`
	AudioPath string `json:"audio_path"`
	CreatedAt any    `json:"created_at"`
	UpdatedAt any    `json:"updated_at"`
}

// ===== Gateway =====

type Gateway struct {
	contentBase       *url.URL
	ratingsBase       *url.URL
	usersBase         *url.URL
	notificationsBase *url.URL
	httpClient        *http.Client
}

func main() {
	port := getenv("PORT", "8080")

	contentURL := getenv("CONTENT_URL", "http://content:8080")
	ratingsURL := getenv("RATINGS_URL", "http://ratings:8080")
	usersURL := getenv("USERS_URL", "http://users:8080")
	notificationsURL := getenv("NOTIFICATIONS_URL", "http://notifications:8080")

	cb, err := url.Parse(contentURL)
	if err != nil {
		log.Fatalf("invalid CONTENT_URL: %v", err)
	}
	rb, err := url.Parse(ratingsURL)
	if err != nil {
		log.Fatalf("invalid RATINGS_URL: %v", err)
	}
	ub, err := url.Parse(usersURL)
	if err != nil {
		log.Fatalf("invalid USERS_URL: %v", err)
	}
	nb, err := url.Parse(notificationsURL)
	if err != nil {
		log.Fatalf("invalid NOTIFICATIONS_URL: %v", err)
	}

	gw := &Gateway{
		httpClient:        &http.Client{Timeout: 8 * time.Second},
		contentBase:       cb,
		ratingsBase:       rb,
		usersBase:         ub,
		notificationsBase: nb,
	}

	r := mux.NewRouter()

	// Health (gateway)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}).Methods(http.MethodGet)

	// ===== Users proxy endpoints =====
	r.HandleFunc("/api/register", gw.proxyUsers("/register")).Methods(http.MethodPost)
	r.HandleFunc("/api/login", gw.proxyUsers("/login")).Methods(http.MethodPost)
	r.HandleFunc("/api/users/health", gw.proxyUsers("/health")).Methods(http.MethodGet)
	r.HandleFunc("/api/users/healthz", gw.proxyUsers("/health")).Methods(http.MethodGet)

	// ===== Notifications proxy endpoints =====
	r.HandleFunc("/api/notifications", gw.proxyNotifications("/notifications")).Methods(http.MethodGet)

	// ===== Content proxy endpoints =====
	r.HandleFunc("/api/content/artists", gw.proxyContent("/api/artists")).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/api/content/artists/{id}", gw.artistDetailsOrProxy()).Methods(http.MethodGet, http.MethodPut, http.MethodDelete)
	r.HandleFunc("/api/content/artists/{id}/albums", gw.proxyContentWithVar("/api/artists/{id}/albums")).Methods(http.MethodGet)

	r.HandleFunc("/api/content/albums", gw.proxyContent("/api/albums")).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/api/content/albums/{id}", gw.albumDetailsOrProxy()).Methods(http.MethodGet, http.MethodPut, http.MethodDelete)
	r.HandleFunc("/api/content/albums/{id}/songs", gw.proxyContentWithVar("/api/albums/{id}/songs")).Methods(http.MethodGet)

	r.HandleFunc("/api/content/songs", gw.proxyContent("/api/songs")).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/api/content/songs/{id}", gw.proxyContentWithVar("/api/songs/{id}")).Methods(http.MethodGet, http.MethodPut, http.MethodDelete)

	// search
	r.HandleFunc("/api/content/search", gw.proxyContent("/api/search")).Methods(http.MethodGet)

	// ===== Ratings proxy endpoints =====
	r.HandleFunc("/api/ratings", gw.proxyRatings("/api/ratings")).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/api/ratings/{id}", gw.proxyRatingsWithVar("/api/ratings/{id}")).Methods(http.MethodGet, http.MethodDelete)
	r.HandleFunc("/api/ratings/summary", gw.proxyRatings("/api/ratings/summary")).Methods(http.MethodGet)

	addr := "0.0.0.0:" + port
	log.Printf("API Gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, withCORS(r)))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-User-Role, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ===== Proxy helpers =====

func (g *Gateway) join(base *url.URL, targetPath, rawQuery string) string {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + targetPath
	u.RawQuery = rawQuery
	return u.String()
}

func (g *Gateway) proxyContent(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.pipe(w, r, g.join(g.contentBase, targetPath, r.URL.RawQuery))
	}
}

func (g *Gateway) proxyContentWithVar(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		tp := strings.ReplaceAll(targetPath, "{id}", url.PathEscape(id))
		g.pipe(w, r, g.join(g.contentBase, tp, r.URL.RawQuery))
	}
}

func (g *Gateway) proxyRatings(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.pipe(w, r, g.join(g.ratingsBase, targetPath, r.URL.RawQuery))
	}
}

func (g *Gateway) proxyRatingsWithVar(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		tp := strings.ReplaceAll(targetPath, "{id}", url.PathEscape(id))
		g.pipe(w, r, g.join(g.ratingsBase, tp, r.URL.RawQuery))
	}
}

func (g *Gateway) proxyUsers(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.pipe(w, r, g.join(g.usersBase, targetPath, r.URL.RawQuery))
	}
}

func (g *Gateway) proxyNotifications(targetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.pipe(w, r, g.join(g.notificationsBase, targetPath, r.URL.RawQuery))
	}
}

// pipe forwards request to targetURL and streams response back
func (g *Gateway) pipe(w http.ResponseWriter, r *http.Request, targetURL string) {
	var bodyBytes []byte
	if r.Body != nil {
		defer r.Body.Close()
		bodyBytes, _ = io.ReadAll(r.Body)
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// Forwarded headers
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Proto", schemeFromRequest(r))
	req.Header.Set("X-Real-IP", realIP(r))
	appendForwardedFor(req, r)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ===== Composition endpoints =====

func (g *Gateway) artistDetailsOrProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			g.proxyContentWithVar("/api/artists/{id}").ServeHTTP(w, r)
			return
		}

		id := mux.Vars(r)["id"]
		artistURL := g.join(g.contentBase, "/api/artists/"+url.PathEscape(id), "")
		albumsURL := g.join(g.contentBase, "/api/artists/"+url.PathEscape(id)+"/albums", r.URL.RawQuery)

		var artist Artist
		if err := g.getJSON(r.Context(), artistURL, &artist); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		var albums PageResponse[Album]
		if err := g.getJSON(r.Context(), albumsURL, &albums); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"artist": artist, "albums": albums})
	}
}

func (g *Gateway) albumDetailsOrProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			g.proxyContentWithVar("/api/albums/{id}").ServeHTTP(w, r)
			return
		}

		id := mux.Vars(r)["id"]
		albumURL := g.join(g.contentBase, "/api/albums/"+url.PathEscape(id), "")
		songsURL := g.join(g.contentBase, "/api/albums/"+url.PathEscape(id)+"/songs", r.URL.RawQuery)

		var album Album
		if err := g.getJSON(r.Context(), albumURL, &album); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		var songs PageResponse[Song]
		if err := g.getJSON(r.Context(), songsURL, &songs); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"album": album, "songs": songs})
	}
}

func (g *Gateway) getJSON(ctx context.Context, urlStr string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return &urlError{status: resp.StatusCode, body: string(b)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type urlError struct {
	status int
	body   string
}

func (e *urlError) Error() string {
	if e.body != "" {
		return e.body
	}
	return "HTTP " + http.StatusText(e.status)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func schemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		return xf
	}
	return "http"
}

func realIP(r *http.Request) string {
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func appendForwardedFor(req *http.Request, r *http.Request) {
	ip := realIP(r)
	if ip == "" {
		return
	}
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+ip)
	} else {
		req.Header.Set("X-Forwarded-For", ip)
	}
}
