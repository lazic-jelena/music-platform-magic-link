package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ============================================================================
// MODELS
// ============================================================================

type PlanType string
type PaymentStatus string

const (
	PlanFree    PlanType = "free"
	PlanPremium PlanType = "premium"
)

const (
	PaymentPending   PaymentStatus = "pending"
	PaymentCompleted PaymentStatus = "completed"
	PaymentFailed    PaymentStatus = "failed"
	PaymentCancelled PaymentStatus = "cancelled"
)

type Subscription struct {
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID        string             `json:"userId" bson:"userId" validate:"required"`
	PlanType      PlanType           `json:"planType" bson:"planType" validate:"required"`
	PaymentStatus PaymentStatus      `json:"paymentStatus" bson:"paymentStatus"`
	StartDate     time.Time          `json:"startDate" bson:"startDate"`
	EndDate       time.Time          `json:"endDate" bson:"endDate"`
	CreatedAt     time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt     time.Time          `json:"updatedAt" bson:"updatedAt"`
}

type CreateSubscriptionRequest struct {
	UserID   string   `json:"userId" validate:"required"`
	PlanType PlanType `json:"planType" validate:"required"`
}

type UpdateSubscriptionRequest struct {
	PlanType      *PlanType      `json:"planType,omitempty"`
	PaymentStatus *PaymentStatus `json:"paymentStatus,omitempty"`
	EndDate       *time.Time     `json:"endDate,omitempty"`
}

// IsActive checks if the subscription is currently active
func (s *Subscription) IsActive() bool {
	now := time.Now()
	return s.PaymentStatus == PaymentCompleted &&
		now.After(s.StartDate) &&
		now.Before(s.EndDate)
}

// CalculateEndDate calculates the end date based on plan type
func CalculateEndDate(planType PlanType, startDate time.Time) time.Time {
	if planType == PlanFree {
		// Free plan never expires (set to 100 years from now)
		return startDate.AddDate(100, 0, 0)
	}
	// Premium plan is monthly
	return startDate.AddDate(0, 1, 0)
}

// ============================================================================
// REPOSITORY
// ============================================================================

type SubscriptionRepository struct {
	collection *mongo.Collection
}

func NewSubscriptionRepository(db *mongo.Database) *SubscriptionRepository {
	collection := db.Collection("subscriptions")

	// Create index on userId for faster lookups
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	indexModel := mongo.IndexModel{
		Keys: bson.D{{Key: "userId", Value: 1}},
	}
	collection.Indexes().CreateOne(ctx, indexModel)

	return &SubscriptionRepository{
		collection: collection,
	}
}

func (r *SubscriptionRepository) Create(ctx context.Context, sub *Subscription) error {
	sub.CreatedAt = time.Now()
	sub.UpdatedAt = time.Now()

	result, err := r.collection.InsertOne(ctx, sub)
	if err != nil {
		return err
	}

	sub.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (r *SubscriptionRepository) GetByID(ctx context.Context, id string) (*Subscription, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New("invalid subscription ID")
	}

	var sub Subscription
	err = r.collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&sub)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("subscription not found")
		}
		return nil, err
	}

	return &sub, nil
}

func (r *SubscriptionRepository) GetByUserID(ctx context.Context, userID string) (*Subscription, error) {
	var sub Subscription

	// Get the most recent subscription for the user
	opts := options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	err := r.collection.FindOne(ctx, bson.M{"userId": userID}, opts).Decode(&sub)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("subscription not found for user")
		}
		return nil, err
	}

	return &sub, nil
}

func (r *SubscriptionRepository) List(ctx context.Context, limit, offset int) ([]*Subscription, error) {
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var subscriptions []*Subscription
	if err = cursor.All(ctx, &subscriptions); err != nil {
		return nil, err
	}

	return subscriptions, nil
}

func (r *SubscriptionRepository) Update(ctx context.Context, id string, update bson.M) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return errors.New("invalid subscription ID")
	}

	update["updatedAt"] = time.Now()

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": update},
	)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("subscription not found")
	}

	return nil
}

func (r *SubscriptionRepository) Delete(ctx context.Context, id string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return errors.New("invalid subscription ID")
	}

	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("subscription not found")
	}

	return nil
}

// ============================================================================
// HANDLERS
// ============================================================================

type SubscriptionHandler struct {
	repo *SubscriptionRepository
}

func NewSubscriptionHandler(repo *SubscriptionRepository) *SubscriptionHandler {
	return &SubscriptionHandler{repo: repo}
}

func (h *SubscriptionHandler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	var req CreateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == "" || (req.PlanType != PlanFree && req.PlanType != PlanPremium) {
		respondError(w, http.StatusBadRequest, "UserID and valid PlanType are required")
		return
	}

	startDate := time.Now()
	endDate := CalculateEndDate(req.PlanType, startDate)

	paymentStatus := PaymentCompleted
	if req.PlanType == PlanPremium {
		paymentStatus = PaymentPending
	}

	subscription := &Subscription{
		UserID:        req.UserID,
		PlanType:      req.PlanType,
		PaymentStatus: paymentStatus,
		StartDate:     startDate,
		EndDate:       endDate,
	}

	if err := h.repo.Create(r.Context(), subscription); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create subscription")
		return
	}

	respondJSON(w, http.StatusCreated, subscription)
}

func (h *SubscriptionHandler) GetSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	subscription, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, subscription)
}

func (h *SubscriptionHandler) GetUserSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]

	subscription, err := h.repo.GetByUserID(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, subscription)
}

func (h *SubscriptionHandler) ListSubscriptions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	subscriptions, err := h.repo.List(r.Context(), limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve subscriptions")
		return
	}

	respondJSON(w, http.StatusOK, subscriptions)
}

func (h *SubscriptionHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req UpdateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	update := bson.M{}
	if req.PlanType != nil {
		update["planType"] = *req.PlanType
	}
	if req.PaymentStatus != nil {
		update["paymentStatus"] = *req.PaymentStatus
	}
	if req.EndDate != nil {
		update["endDate"] = *req.EndDate
	}

	if len(update) == 0 {
		respondError(w, http.StatusBadRequest, "No fields to update")
		return
	}

	if err := h.repo.Update(r.Context(), id, update); err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	subscription, _ := h.repo.GetByID(r.Context(), id)
	respondJSON(w, http.StatusOK, subscription)
}

func (h *SubscriptionHandler) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := h.repo.Delete(r.Context(), id); err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

func main() {
	// MongoDB connection
	mongoURI := getEnv("MONGO_URI", "mongodb://localhost:27017")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer client.Disconnect(context.Background())

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}
	log.Println("Connected to MongoDB successfully")

	// Initialize repository and handler
	db := client.Database("musicplatform")
	repo := NewSubscriptionRepository(db)
	handler := NewSubscriptionHandler(repo)

	// Setup router
	router := mux.NewRouter()
	router.HandleFunc("/subscriptions", handler.CreateSubscription).Methods("POST")
	router.HandleFunc("/subscriptions/{id}", handler.GetSubscription).Methods("GET")
	router.HandleFunc("/subscriptions", handler.ListSubscriptions).Methods("GET")
	router.HandleFunc("/subscriptions/{id}", handler.UpdateSubscription).Methods("PUT")
	router.HandleFunc("/subscriptions/{id}", handler.DeleteSubscription).Methods("DELETE")
	router.HandleFunc("/subscriptions/user/{userId}", handler.GetUserSubscription).Methods("GET")
	router.HandleFunc("/health", healthCheck).Methods("GET")

	// Server configuration
	port := getEnv("PORT", "8080")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Starting subscription service on port %s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
