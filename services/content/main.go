package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ===== Models (uskladjeno sa 1.4 + 1.5 + 1.6 + 1.8) =====

type Artist struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Bio       string             `json:"bio" bson:"bio"`
	Genres    []string           `json:"genres" bson:"genres,omitempty"` // 1.4 + 1.8
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
}

type Album struct {
	ID          primitive.ObjectID   `json:"id" bson:"_id,omitempty"`
	Title       string               `json:"title" bson:"title"`
	Genre       string               `json:"genre" bson:"genre,omitempty"` // 1.5 + 1.8
	ArtistID    primitive.ObjectID   `json:"artist_id" bson:"artist_id,omitempty"`
	ArtistIDs   []primitive.ObjectID `json:"artist_ids" bson:"artist_ids,omitempty"` // za vise artista
	ReleaseYear int                  `json:"release_year" bson:"release_year"`
	CreatedAt   time.Time            `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at" bson:"updated_at"`
}

type Song struct {
	ID        primitive.ObjectID   `json:"id" bson:"_id,omitempty"`
	Title     string               `json:"title" bson:"title"`
	Genre     string               `json:"genre" bson:"genre,omitempty"` // 1.8
	AlbumID   primitive.ObjectID   `json:"album_id" bson:"album_id"`
	ArtistID  primitive.ObjectID   `json:"artist_id" bson:"artist_id,omitempty"`
	ArtistIDs []primitive.ObjectID `json:"artist_ids" bson:"artist_ids,omitempty"`
	Duration  int                  `json:"duration" bson:"duration"`
	TrackNum  int                  `json:"track_number" bson:"track_number"`
	AudioPath string               `json:"audio_path" bson:"audio_path,omitempty"` // kasnije HDFS
	CreatedAt time.Time            `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time            `json:"updated_at" bson:"updated_at"`
}

type PageResponse struct {
	Items any   `json:"items"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
	Total int64 `json:"total"`
}

// ===== Database =====

var db *mongo.Database

func initDB() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017/content_db"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("MongoDB connection error: %v", err)
	}

	db = client.Database("content_db")
	log.Println("Connected to MongoDB (content_db)")
}

func main() {
	initDB()

	// Seed ako je ukljucen i baza prazna
	if isSeedEnabled() {
		if err := seedIfEmpty(); err != nil {
			log.Printf("AUTO_SEED failed: %v", err)
		}
	}

	r := mux.NewRouter()

	// Health check
	r.HandleFunc("/health", healthCheck).Methods("GET")
	r.HandleFunc("/healthz", healthCheck).Methods("GET")

	// ===== SEARCH route (FIX za tvoj 404) =====
	// Front ti zove /api/content/search?... => dodajemo oba puta da radi i preko proxy-a i direktno
	r.HandleFunc("/api/search", searchContent).Methods("GET")
	r.HandleFunc("/api/content/search", searchContent).Methods("GET")

	// ===== Artist routes =====
	r.HandleFunc("/api/artists", requireRoleA(createArtist)).Methods("POST")
	r.HandleFunc("/api/artists", getArtists).Methods("GET")
	r.HandleFunc("/api/artists/{id}", getArtist).Methods("GET")
	r.HandleFunc("/api/artists/{id}", requireRoleA(updateArtist)).Methods("PUT")
	r.HandleFunc("/api/artists/{id}", requireRoleA(deleteArtist)).Methods("DELETE")

	// Browse helper: albums by artist (1.6)
	r.HandleFunc("/api/artists/{id}/albums", getAlbumsByArtist).Methods("GET")

	// ===== Album routes =====
	r.HandleFunc("/api/albums", requireRoleA(createAlbum)).Methods("POST")
	r.HandleFunc("/api/albums", getAlbums).Methods("GET")
	r.HandleFunc("/api/albums/{id}", getAlbum).Methods("GET")
	r.HandleFunc("/api/albums/{id}", requireRoleA(updateAlbum)).Methods("PUT")
	r.HandleFunc("/api/albums/{id}", requireRoleA(deleteAlbum)).Methods("DELETE")

	// Browse helper: songs by album (1.6)
	r.HandleFunc("/api/albums/{id}/songs", getSongsByAlbum).Methods("GET")

	// ===== Song routes =====
	r.HandleFunc("/api/songs", requireRoleA(createSong)).Methods("POST")
	r.HandleFunc("/api/songs", getSongs).Methods("GET")
	r.HandleFunc("/api/songs/{id}", getSong).Methods("GET")
	r.HandleFunc("/api/songs/{id}", requireRoleA(updateSong)).Methods("PUT")
	r.HandleFunc("/api/songs/{id}", requireRoleA(deleteSong)).Methods("DELETE")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Content service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// ===== Helpers =====

func healthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

func parsePageLimit(r *http.Request) (page int, limit int) {
	page = 1
	limit = 20

	if v := strings.TrimSpace(r.URL.Query().Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	return
}

func parseObjectID(hex string) (primitive.ObjectID, bool) {
	hex = strings.TrimSpace(hex)
	if hex == "" {
		return primitive.NilObjectID, false
	}
	oid, err := primitive.ObjectIDFromHex(hex)
	if err != nil {
		return primitive.NilObjectID, false
	}
	return oid, true
}

func buildNameSearchFilter(q string, field string) bson.M {
	q = strings.TrimSpace(q)
	if q == "" {
		return bson.M{}
	}
	return bson.M{field: bson.M{"$regex": q, "$options": "i"}}
}

func isSeedEnabled() bool {
	// podrzi AUTO_SEED i AUTOSEED (da ne gubimo vreme)
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTO_SEED")))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(os.Getenv("AUTOSEED")))
	}
	return v == "true" || v == "1" || v == "yes"
}

// ===== Role middleware (kao sto vec imas) =====

func requireRoleA(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		if role != "A" {
			respondError(w, http.StatusForbidden, "Access denied. Requires role A.")
			return
		}
		next.ServeHTTP(w, r)
	}
}

// ===== SEARCH (NOVO) =====
// Vraća format koji tvoj browse.html očekuje:
// { "artists": {items,page,limit,total}, "albums": {...}, "songs": {...} }
func searchContent(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePageLimit(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// ----- Artists -----
	artistFilter := bson.M{}
	for k, v := range buildNameSearchFilter(q, "name") {
		artistFilter[k] = v
	}
	if genre != "" {
		artistFilter["genres"] = genre
	}

	artistsTotal, err := db.Collection("artists").CountDocuments(ctx, artistFilter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to search artists")
		return
	}

	artistSkip := int64((page - 1) * limit)
	artistOpts := options.Find().
		SetSkip(artistSkip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "name", Value: 1}})

	artistCur, err := db.Collection("artists").Find(ctx, artistFilter, artistOpts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch artists")
		return
	}
	var artists []Artist
	if err := artistCur.All(ctx, &artists); err != nil {
		_ = artistCur.Close(ctx)
		respondError(w, http.StatusInternalServerError, "Failed to decode artists")
		return
	}
	_ = artistCur.Close(ctx)

	// ----- Albums -----
	albumFilter := bson.M{}
	for k, v := range buildNameSearchFilter(q, "title") {
		albumFilter[k] = v
	}
	if genre != "" {
		albumFilter["genre"] = genre
	}

	albumsTotal, err := db.Collection("albums").CountDocuments(ctx, albumFilter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to search albums")
		return
	}

	albumSkip := int64((page - 1) * limit)
	albumOpts := options.Find().
		SetSkip(albumSkip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "release_year", Value: -1}, {Key: "title", Value: 1}})

	albumCur, err := db.Collection("albums").Find(ctx, albumFilter, albumOpts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch albums")
		return
	}
	var albums []Album
	if err := albumCur.All(ctx, &albums); err != nil {
		_ = albumCur.Close(ctx)
		respondError(w, http.StatusInternalServerError, "Failed to decode albums")
		return
	}
	_ = albumCur.Close(ctx)

	// ----- Songs -----
	songFilter := bson.M{}
	for k, v := range buildNameSearchFilter(q, "title") {
		songFilter[k] = v
	}
	if genre != "" {
		songFilter["genre"] = genre
	}

	songsTotal, err := db.Collection("songs").CountDocuments(ctx, songFilter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to search songs")
		return
	}

	songSkip := int64((page - 1) * limit)
	songOpts := options.Find().
		SetSkip(songSkip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "title", Value: 1}})

	songCur, err := db.Collection("songs").Find(ctx, songFilter, songOpts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch songs")
		return
	}
	var songs []Song
	if err := songCur.All(ctx, &songs); err != nil {
		_ = songCur.Close(ctx)
		respondError(w, http.StatusInternalServerError, "Failed to decode songs")
		return
	}
	_ = songCur.Close(ctx)

	respondJSON(w, http.StatusOK, map[string]any{
		"artists": PageResponse{Items: artists, Page: page, Limit: limit, Total: artistsTotal},
		"albums":  PageResponse{Items: albums, Page: page, Limit: limit, Total: albumsTotal},
		"songs":   PageResponse{Items: songs, Page: page, Limit: limit, Total: songsTotal},
	})
}

// ===== CRUD + Browse + Filter =====

// --- ARTISTS ---

func createArtist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Bio    string   `json:"bio"`
		Genres []string `json:"genres"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Bio = strings.TrimSpace(in.Bio)
	if in.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	now := time.Now().UTC()
	artist := Artist{
		Name:      in.Name,
		Bio:       in.Bio,
		Genres:    in.Genres,
		CreatedAt: now,
		UpdatedAt: now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("artists").InsertOne(ctx, artist)
	if err != nil {
		log.Printf("Error creating artist: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create artist")
		return
	}
	artist.ID = res.InsertedID.(primitive.ObjectID)
	respondJSON(w, http.StatusCreated, artist)
}

func getArtists(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePageLimit(r)
	q := r.URL.Query().Get("q")
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))

	filter := bson.M{}
	// search by name
	for k, v := range buildNameSearchFilter(q, "name") {
		filter[k] = v
	}
	// filter by genre (array match)
	if genre != "" {
		filter["genres"] = genre
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := db.Collection("artists").CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("Error counting artists: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to fetch artists")
		return
	}

	skip := int64((page - 1) * limit)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "name", Value: 1}})

	cursor, err := db.Collection("artists").Find(ctx, filter, opts)
	if err != nil {
		log.Printf("Error fetching artists: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to fetch artists")
		return
	}
	defer cursor.Close(ctx)

	var artists []Artist
	if err := cursor.All(ctx, &artists); err != nil {
		log.Printf("Error decoding artists: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to decode artists")
		return
	}

	respondJSON(w, http.StatusOK, PageResponse{
		Items: artists,
		Page:  page,
		Limit: limit,
		Total: total,
	})
}

func getArtist(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid artist ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var artist Artist
	err = db.Collection("artists").FindOne(ctx, bson.M{"_id": oid}).Decode(&artist)
	if err != nil {
		respondError(w, http.StatusNotFound, "Artist not found")
		return
	}
	respondJSON(w, http.StatusOK, artist)
}

func updateArtist(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid artist ID")
		return
	}

	var in struct {
		Name   *string  `json:"name"`
		Bio    *string  `json:"bio"`
		Genres []string `json:"genres"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	update := bson.M{"updated_at": time.Now().UTC()}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n != "" {
			update["name"] = n
		}
	}
	if in.Bio != nil {
		update["bio"] = strings.TrimSpace(*in.Bio)
	}
	// ako u payloadu postoji genres (moze i prazno, da se obrise)
	if _, ok := r.URL.Query()["genres"]; ok || in.Genres != nil {
		update["genres"] = in.Genres
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("artists").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": update})
	if err != nil || res.MatchedCount == 0 {
		respondError(w, http.StatusNotFound, "Artist not found")
		return
	}

	var artist Artist
	_ = db.Collection("artists").FindOne(ctx, bson.M{"_id": oid}).Decode(&artist)
	respondJSON(w, http.StatusOK, artist)
}

func deleteArtist(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid artist ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("artists").DeleteOne(ctx, bson.M{"_id": oid})
	if err != nil || res.DeletedCount == 0 {
		respondError(w, http.StatusNotFound, "Artist not found")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "Artist deleted"})
}

// Browse helper: /api/artists/{id}/albums
func getAlbumsByArtist(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	artistOID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid artist ID")
		return
	}

	page, limit := parsePageLimit(r)
	q := r.URL.Query().Get("q")
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))

	filter := bson.M{
		"$or": []bson.M{
			{"artist_id": artistOID},
			{"artist_ids": artistOID},
		},
	}
	for k, v := range buildNameSearchFilter(q, "title") {
		filter[k] = v
	}
	if genre != "" {
		filter["genre"] = genre
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := db.Collection("albums").CountDocuments(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch albums")
		return
	}

	skip := int64((page - 1) * limit)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "release_year", Value: -1}, {Key: "title", Value: 1}})

	cur, err := db.Collection("albums").Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch albums")
		return
	}
	defer cur.Close(ctx)

	var albums []Album
	if err := cur.All(ctx, &albums); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode albums")
		return
	}

	respondJSON(w, http.StatusOK, PageResponse{Items: albums, Page: page, Limit: limit, Total: total})
}

// --- ALBUMS ---

func createAlbum(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title       string   `json:"title"`
		Genre       string   `json:"genre"`
		ReleaseYear int      `json:"release_year"`
		ArtistID    string   `json:"artist_id"`
		ArtistIDs   []string `json:"artist_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	in.Genre = strings.TrimSpace(in.Genre)
	if in.Title == "" {
		respondError(w, http.StatusBadRequest, "Title is required")
		return
	}

	var artistOID primitive.ObjectID
	var artistIDs []primitive.ObjectID

	if oid, ok := parseObjectID(in.ArtistID); ok {
		artistOID = oid
	}
	for _, s := range in.ArtistIDs {
		if oid, ok := parseObjectID(s); ok {
			artistIDs = append(artistIDs, oid)
		}
	}
	// ako nista od artist_ids, a imamo artist_id, ubaci u artist_ids
	if len(artistIDs) == 0 && artistOID != primitive.NilObjectID {
		artistIDs = []primitive.ObjectID{artistOID}
	}

	now := time.Now().UTC()
	album := Album{
		Title:       in.Title,
		Genre:       in.Genre,
		ArtistID:    artistOID,
		ArtistIDs:   artistIDs,
		ReleaseYear: in.ReleaseYear,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("albums").InsertOne(ctx, album)
	if err != nil {
		log.Printf("Error creating album: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create album")
		return
	}
	album.ID = res.InsertedID.(primitive.ObjectID)
	respondJSON(w, http.StatusCreated, album)
}

func getAlbums(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePageLimit(r)
	q := r.URL.Query().Get("q")
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))
	artistId := strings.TrimSpace(r.URL.Query().Get("artistId"))

	filter := bson.M{}
	for k, v := range buildNameSearchFilter(q, "title") {
		filter[k] = v
	}
	if genre != "" {
		filter["genre"] = genre
	}
	if oid, ok := parseObjectID(artistId); ok {
		filter["$or"] = []bson.M{
			{"artist_id": oid},
			{"artist_ids": oid},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := db.Collection("albums").CountDocuments(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch albums")
		return
	}

	skip := int64((page - 1) * limit)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "release_year", Value: -1}, {Key: "title", Value: 1}})

	cur, err := db.Collection("albums").Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch albums")
		return
	}
	defer cur.Close(ctx)

	var albums []Album
	if err := cur.All(ctx, &albums); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode albums")
		return
	}

	respondJSON(w, http.StatusOK, PageResponse{Items: albums, Page: page, Limit: limit, Total: total})
}

func getAlbum(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid album ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var album Album
	err = db.Collection("albums").FindOne(ctx, bson.M{"_id": oid}).Decode(&album)
	if err != nil {
		respondError(w, http.StatusNotFound, "Album not found")
		return
	}
	respondJSON(w, http.StatusOK, album)
}

func updateAlbum(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid album ID")
		return
	}

	var in struct {
		Title       *string  `json:"title"`
		Genre       *string  `json:"genre"`
		ReleaseYear *int     `json:"release_year"`
		ArtistID    *string  `json:"artist_id"`
		ArtistIDs   []string `json:"artist_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	update := bson.M{"updated_at": time.Now().UTC()}
	if in.Title != nil {
		t := strings.TrimSpace(*in.Title)
		if t != "" {
			update["title"] = t
		}
	}
	if in.Genre != nil {
		update["genre"] = strings.TrimSpace(*in.Genre)
	}
	if in.ReleaseYear != nil {
		update["release_year"] = *in.ReleaseYear
	}
	if in.ArtistID != nil {
		if a, ok := parseObjectID(*in.ArtistID); ok {
			update["artist_id"] = a
		}
	}
	if in.ArtistIDs != nil {
		var arr []primitive.ObjectID
		for _, s := range in.ArtistIDs {
			if a, ok := parseObjectID(s); ok {
				arr = append(arr, a)
			}
		}
		update["artist_ids"] = arr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("albums").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": update})
	if err != nil || res.MatchedCount == 0 {
		respondError(w, http.StatusNotFound, "Album not found")
		return
	}

	var album Album
	_ = db.Collection("albums").FindOne(ctx, bson.M{"_id": oid}).Decode(&album)
	respondJSON(w, http.StatusOK, album)
}

func deleteAlbum(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid album ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("albums").DeleteOne(ctx, bson.M{"_id": oid})
	if err != nil || res.DeletedCount == 0 {
		respondError(w, http.StatusNotFound, "Album not found")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "Album deleted"})
}

// Browse helper: /api/albums/{id}/songs
func getSongsByAlbum(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	albumOID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid album ID")
		return
	}

	page, limit := parsePageLimit(r)
	q := r.URL.Query().Get("q")
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))

	filter := bson.M{"album_id": albumOID}
	for k, v := range buildNameSearchFilter(q, "title") {
		filter[k] = v
	}
	if genre != "" {
		filter["genre"] = genre
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := db.Collection("songs").CountDocuments(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch songs")
		return
	}

	skip := int64((page - 1) * limit)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "track_number", Value: 1}, {Key: "title", Value: 1}})

	cur, err := db.Collection("songs").Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch songs")
		return
	}
	defer cur.Close(ctx)

	var songs []Song
	if err := cur.All(ctx, &songs); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode songs")
		return
	}

	respondJSON(w, http.StatusOK, PageResponse{Items: songs, Page: page, Limit: limit, Total: total})
}

// --- SONGS ---

func createSong(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title     string   `json:"title"`
		Genre     string   `json:"genre"`
		AlbumID   string   `json:"album_id"`
		ArtistID  string   `json:"artist_id"`
		ArtistIDs []string `json:"artist_ids"`
		Duration  int      `json:"duration"`
		TrackNum  int      `json:"track_number"`
		AudioPath string   `json:"audio_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	in.Title = strings.TrimSpace(in.Title)
	in.Genre = strings.TrimSpace(in.Genre)
	if in.Title == "" {
		respondError(w, http.StatusBadRequest, "Title is required")
		return
	}
	albumOID, ok := parseObjectID(in.AlbumID)
	if !ok {
		respondError(w, http.StatusBadRequest, "Invalid album_id")
		return
	}

	var artistOID primitive.ObjectID
	var artistIDs []primitive.ObjectID

	if oid, ok := parseObjectID(in.ArtistID); ok {
		artistOID = oid
	}
	for _, s := range in.ArtistIDs {
		if oid, ok := parseObjectID(s); ok {
			artistIDs = append(artistIDs, oid)
		}
	}
	if len(artistIDs) == 0 && artistOID != primitive.NilObjectID {
		artistIDs = []primitive.ObjectID{artistOID}
	}

	now := time.Now().UTC()
	song := Song{
		Title:     in.Title,
		Genre:     in.Genre,
		AlbumID:   albumOID,
		ArtistID:  artistOID,
		ArtistIDs: artistIDs,
		Duration:  in.Duration,
		TrackNum:  in.TrackNum,
		AudioPath: strings.TrimSpace(in.AudioPath),
		CreatedAt: now,
		UpdatedAt: now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("songs").InsertOne(ctx, song)
	if err != nil {
		log.Printf("Error creating song: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create song")
		return
	}
	song.ID = res.InsertedID.(primitive.ObjectID)
	respondJSON(w, http.StatusCreated, song)
}

func getSongs(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePageLimit(r)
	q := r.URL.Query().Get("q")
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))
	artistId := strings.TrimSpace(r.URL.Query().Get("artistId"))
	albumId := strings.TrimSpace(r.URL.Query().Get("albumId"))

	filter := bson.M{}
	for k, v := range buildNameSearchFilter(q, "title") {
		filter[k] = v
	}
	if genre != "" {
		filter["genre"] = genre
	}
	if oid, ok := parseObjectID(albumId); ok {
		filter["album_id"] = oid
	}
	if oid, ok := parseObjectID(artistId); ok {
		filter["$or"] = []bson.M{
			{"artist_id": oid},
			{"artist_ids": oid},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := db.Collection("songs").CountDocuments(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch songs")
		return
	}

	skip := int64((page - 1) * limit)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "title", Value: 1}})

	cur, err := db.Collection("songs").Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch songs")
		return
	}
	defer cur.Close(ctx)

	var songs []Song
	if err := cur.All(ctx, &songs); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode songs")
		return
	}

	respondJSON(w, http.StatusOK, PageResponse{Items: songs, Page: page, Limit: limit, Total: total})
}

func getSong(w http.ResponseWriter, r *http.Request) {
	rawID := mux.Vars(r)["id"]
	rawID = strings.TrimSpace(rawID)

	// hardening: nekad ljudi greškom proslede "id?x=y" ili "id/..."
	if i := strings.Index(rawID, "?"); i >= 0 {
		rawID = rawID[:i]
	}
	if i := strings.Index(rawID, "/"); i >= 0 {
		rawID = rawID[:i]
	}

	oid, err := primitive.ObjectIDFromHex(rawID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid song ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var song Song
	err = db.Collection("songs").FindOne(ctx, bson.M{"_id": oid}).Decode(&song)
	if err != nil {
		respondError(w, http.StatusNotFound, "Song not found")
		return
	}

	// strict check (paranoia): mora da se vrati baš taj ID
	if song.ID != oid {
		log.Printf("BUG: getSong mismatch. requested=%s got=%s", oid.Hex(), song.ID.Hex())
		respondError(w, http.StatusInternalServerError, "Song ID mismatch (server bug)")
		return
	}

	respondJSON(w, http.StatusOK, song)
}

func updateSong(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid song ID")
		return
	}

	var in struct {
		Title     *string  `json:"title"`
		Genre     *string  `json:"genre"`
		AlbumID   *string  `json:"album_id"`
		ArtistID  *string  `json:"artist_id"`
		ArtistIDs []string `json:"artist_ids"`
		Duration  *int     `json:"duration"`
		TrackNum  *int     `json:"track_number"`
		AudioPath *string  `json:"audio_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	update := bson.M{"updated_at": time.Now().UTC()}
	if in.Title != nil {
		t := strings.TrimSpace(*in.Title)
		if t != "" {
			update["title"] = t
		}
	}
	if in.Genre != nil {
		update["genre"] = strings.TrimSpace(*in.Genre)
	}
	if in.AlbumID != nil {
		if a, ok := parseObjectID(*in.AlbumID); ok {
			update["album_id"] = a
		}
	}
	if in.ArtistID != nil {
		if a, ok := parseObjectID(*in.ArtistID); ok {
			update["artist_id"] = a
		}
	}
	if in.ArtistIDs != nil {
		var arr []primitive.ObjectID
		for _, s := range in.ArtistIDs {
			if a, ok := parseObjectID(s); ok {
				arr = append(arr, a)
			}
		}
		update["artist_ids"] = arr
	}
	if in.Duration != nil {
		update["duration"] = *in.Duration
	}
	if in.TrackNum != nil {
		update["track_number"] = *in.TrackNum
	}
	if in.AudioPath != nil {
		update["audio_path"] = strings.TrimSpace(*in.AudioPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("songs").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": update})
	if err != nil || res.MatchedCount == 0 {
		respondError(w, http.StatusNotFound, "Song not found")
		return
	}

	var song Song
	_ = db.Collection("songs").FindOne(ctx, bson.M{"_id": oid}).Decode(&song)
	respondJSON(w, http.StatusOK, song)
}

func deleteSong(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid song ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := db.Collection("songs").DeleteOne(ctx, bson.M{"_id": oid})
	if err != nil || res.DeletedCount == 0 {
		respondError(w, http.StatusNotFound, "Song not found")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "Song deleted"})
}

// ===== AUTO SEED =====

func seedIfEmpty() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cnt, err := db.Collection("artists").CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}
	if cnt > 0 {
		log.Println("AUTO_SEED: artists not empty, skipping.")
		return nil
	}

	now := time.Now().UTC()

	// Artists
	a1 := Artist{Name: "The Rockers", Bio: "Rock band", Genres: []string{"Rock"}, CreatedAt: now, UpdatedAt: now}
	a2 := Artist{Name: "Pop Star", Bio: "Pop artist", Genres: []string{"Pop"}, CreatedAt: now, UpdatedAt: now}

	resA, err := db.Collection("artists").InsertMany(ctx, []any{a1, a2})
	if err != nil {
		return err
	}
	artist1 := resA.InsertedIDs[0].(primitive.ObjectID)
	artist2 := resA.InsertedIDs[1].(primitive.ObjectID)

	// Albums
	al1 := Album{Title: "Rock Album", Genre: "Rock", ArtistID: artist1, ArtistIDs: []primitive.ObjectID{artist1}, ReleaseYear: 2020, CreatedAt: now, UpdatedAt: now}
	al2 := Album{Title: "Pop Album", Genre: "Pop", ArtistID: artist2, ArtistIDs: []primitive.ObjectID{artist2}, ReleaseYear: 2022, CreatedAt: now, UpdatedAt: now}

	resAl, err := db.Collection("albums").InsertMany(ctx, []any{al1, al2})
	if err != nil {
		return err
	}
	album1 := resAl.InsertedIDs[0].(primitive.ObjectID)
	album2 := resAl.InsertedIDs[1].(primitive.ObjectID)

	// Songs
	songs := []any{
		Song{Title: "Rock Song A", Genre: "Rock", AlbumID: album1, ArtistID: artist1, ArtistIDs: []primitive.ObjectID{artist1}, Duration: 210, TrackNum: 1, CreatedAt: now, UpdatedAt: now},
		Song{Title: "Rock Song B", Genre: "Rock", AlbumID: album1, ArtistID: artist1, ArtistIDs: []primitive.ObjectID{artist1}, Duration: 185, TrackNum: 2, CreatedAt: now, UpdatedAt: now},
		Song{Title: "Pop Song A", Genre: "Pop", AlbumID: album2, ArtistID: artist2, ArtistIDs: []primitive.ObjectID{artist2}, Duration: 200, TrackNum: 1, CreatedAt: now, UpdatedAt: now},
		Song{Title: "Pop Song B", Genre: "Pop", AlbumID: album2, ArtistID: artist2, ArtistIDs: []primitive.ObjectID{artist2}, Duration: 195, TrackNum: 2, CreatedAt: now, UpdatedAt: now},
	}

	if _, err := db.Collection("songs").InsertMany(ctx, songs); err != nil {
		return err
	}

	log.Println("AUTO_SEED: inserted sample artists, albums, songs.")
	return nil
}
