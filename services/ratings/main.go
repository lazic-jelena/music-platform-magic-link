package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"net/url"
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

type Rating struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SongID    primitive.ObjectID `bson:"song_id" json:"song_id"`
	UserID    string             `bson:"user_id" json:"user_id"`
	Value     float64            `bson:"value" json:"value"` // NOW: 0.0..5.0 (step 0.5)
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

type RatingIn struct {
	SongID string  `json:"song_id"`
	UserID string  `json:"user_id"`
	Value  float64 `json:"value"` // NOW: 0.0..5.0 (step 0.5)
}

type PageResponse[T any] struct {
	Items []T `json:"items"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Total int `json:"total"`
}

type App struct {
	db         *mongo.Database
	ratingsCol *mongo.Collection

	contentBase *url.URL
	httpClient  *http.Client
}

func main() {
	port := getenv("PORT", "8080")
	mongoURI := getenv("MONGO_URI", "mongodb://localhost:27017/ratings_db")
	contentURL := getenv("CONTENT_URL", "http://content:8080") // docker network: "content"

	cb, err := url.Parse(contentURL)
	if err != nil {
		log.Fatalf("invalid CONTENT_URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("mongo connect failed: %v", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("mongo ping failed: %v", err)
	}

	dbName := dbNameFromMongoURI(mongoURI)
	db := client.Database(dbName)
	col := db.Collection("ratings")

	// unique (song_id, user_id) => POST behaves like upsert
	_, _ = col.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{
			{Key: "song_id", Value: 1},
			{Key: "user_id", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})

	app := &App{
		db:          db,
		ratingsCol:  col,
		contentBase: cb,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}

	r := mux.NewRouter()
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}).Methods("GET")

	// Ratings API
	r.HandleFunc("/api/ratings", app.createOrUpdateRating()).Methods("POST")
	r.HandleFunc("/api/ratings", app.listRatings()).Methods("GET")
	r.HandleFunc("/api/ratings/{id}", app.getRatingByID()).Methods("GET")
	r.HandleFunc("/api/ratings/{id}", app.deleteRatingByID()).Methods("DELETE")

	addr := "0.0.0.0:" + port
	log.Printf("Ratings service listening on %s (db=%s)", addr, dbName)
	log.Fatal(http.ListenAndServe(addr, r))
}

// ===== Validation helpers =====

func isHalfStep(v float64) bool {
	// valid if v * 2 is (almost) an integer
	x := v * 2
	return math.Abs(x-math.Round(x)) < 1e-9
}

func clampRating(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 5 {
		return 5
	}
	// snap to half
	return math.Round(v*2) / 2
}

// ===== Handlers =====

func (a *App) createOrUpdateRating() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in RatingIn
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}

		in.UserID = strings.TrimSpace(in.UserID)
		in.SongID = strings.TrimSpace(in.SongID)

		if in.UserID == "" || in.SongID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "song_id and user_id are required"})
			return
		}

		// Allow 0.0..5.0 in steps of 0.5 (Newgrounds style)
		if in.Value < 0 || in.Value > 5 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value must be between 0 and 5"})
			return
		}
		if !isHalfStep(in.Value) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value must be in 0.5 steps (e.g. 3.5)"})
			return
		}
		in.Value = clampRating(in.Value)

		songOID, err := primitive.ObjectIDFromHex(in.SongID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "song does not exist"})
			return
		}

		// ===== SYNC CHECK to Content (card #3.9) =====
		exists, status, err := a.songExists(r.Context(), in.SongID)
		if err != nil {
			log.Printf("content check failed (song_id=%s): %v", in.SongID, err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "content service unavailable"})
			return
		}
		if !exists {
			log.Printf("song does not exist (song_id=%s, content_status=%d)", in.SongID, status)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "song does not exist"})
			return
		}

		now := time.Now().UTC()

		filter := bson.M{"song_id": songOID, "user_id": in.UserID}
		update := bson.M{
			"$set": bson.M{
				"value":      in.Value,
				"updated_at": now,
			},
			"$setOnInsert": bson.M{
				"song_id":    songOID,
				"user_id":    in.UserID,
				"created_at": now,
			},
		}

		opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
		var out Rating
		err = a.ratingsCol.FindOneAndUpdate(r.Context(), filter, update, opts).Decode(&out)
		if err != nil {
			log.Printf("db upsert failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		writeJSON(w, http.StatusCreated, out)
	}
}

func (a *App) listRatings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := mustInt(r.URL.Query().Get("page"), 1)
		limit := mustInt(r.URL.Query().Get("limit"), 20)
		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 20
		}
		if limit > 100 {
			limit = 100
		}

		qSong := strings.TrimSpace(r.URL.Query().Get("song_id"))
		qUser := strings.TrimSpace(r.URL.Query().Get("user_id"))

		filter := bson.M{}
		if qUser != "" {
			filter["user_id"] = qUser
		}
		if qSong != "" {
			if oid, err := primitive.ObjectIDFromHex(qSong); err == nil {
				filter["song_id"] = oid
			}
		}

		ctx := r.Context()

		total64, err := a.ratingsCol.CountDocuments(ctx, filter)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		opts := options.Find().
			SetSort(bson.D{{Key: "updated_at", Value: -1}}).
			SetSkip(int64((page - 1) * limit)).
			SetLimit(int64(limit))

		cur, err := a.ratingsCol.Find(ctx, filter, opts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer cur.Close(ctx)

		items := make([]Rating, 0)
		for cur.Next(ctx) {
			var it Rating
			if err := cur.Decode(&it); err == nil {
				items = append(items, it)
			}
		}

		writeJSON(w, http.StatusOK, PageResponse[Rating]{
			Items: items,
			Page:  page,
			Limit: limit,
			Total: int(total64),
		})
	}
}

func (a *App) getRatingByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rating id"})
			return
		}

		var out Rating
		err = a.ratingsCol.FindOne(r.Context(), bson.M{"_id": oid}).Decode(&out)
		if errors.Is(err, mongo.ErrNoDocuments) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func (a *App) deleteRatingByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rating id"})
			return
		}

		res, err := a.ratingsCol.DeleteOne(r.Context(), bson.M{"_id": oid})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		if res.DeletedCount == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	}
}

// ===== Sync check helper =====

func (a *App) songExists(ctx context.Context, songID string) (bool, int, error) {
	// Content: GET /api/songs/{id}
	base := *a.contentBase
	base.Path = strings.TrimRight(a.contentBase.Path, "/") + "/api/songs/" + songID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return false, 0, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return false, resp.StatusCode, nil
	}
	return false, resp.StatusCode, errors.New("unexpected status from content: " + resp.Status)
}

// ===== Utils =====

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

func mustInt(s string, def int) int {
	if strings.TrimSpace(s) == "" {
		return def
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

func dbNameFromMongoURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return "ratings_db"
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		return "ratings_db"
	}
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}
