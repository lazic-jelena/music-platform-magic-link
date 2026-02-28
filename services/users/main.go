package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ===== Models =====

type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username          string             `bson:"username" json:"username"`
	Email             string             `bson:"email" json:"email"`
	FirstName         string             `bson:"firstName" json:"firstName"`
	LastName          string             `bson:"lastName" json:"lastName"`
	HashedPassword    string             `bson:"hashedPassword" json:"-"`
	Role              string             `bson:"role" json:"role"`
	PasswordCreatedAt time.Time          `bson:"passwordCreatedAt" json:"passwordCreatedAt"`
	CreatedAt         time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt         time.Time          `bson:"updatedAt" json:"updatedAt"`
	IsActive          bool               `bson:"isActive" json:"isActive"`

	// ✅ reset password (magic link)
	ResetTokenHash      string    `bson:"resetTokenHash,omitempty" json:"-"`
	ResetTokenExpiresAt time.Time `bson:"resetTokenExpiresAt,omitempty" json:"-"`
}

type RegisterRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateUserRequest struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Email     string `json:"email,omitempty"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// ✅ magic link (forgot + reset password)
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// ===== Globals =====

var (
	userCollection *mongo.Collection

	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,30}$`)
)

// ===== Helpers =====

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func validateEmail(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) == 0 || len(email) > 100 {
		return false
	}
	return emailRegex.MatchString(email)
}

func validateUsername(username string) bool {
	username = strings.TrimSpace(username)
	return usernameRegex.MatchString(username)
}

func validatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Lozinka mora imati najmanje 8 karaktera"
	}
	if len(password) > 100 {
		return false, "Lozinka ne može biti duža od 100 karaktera"
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	if !hasUpper || !hasLower || !hasNumber {
		return false, "Lozinka mora sadržati velika i mala slova i brojeve"
	}
	return true, ""
}

func validateName(name string) bool {
	name = strings.TrimSpace(name)
	return len(name) >= 2 && len(name) <= 50
}

func sanitizeString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, `'`, "&#x27;")
	return s
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func requestCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 6*time.Second)
}

// FIX: CORS middleware i dalje ostaje, ali OPTIONS treba vraćati 204
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dev-friendly. Ako želiš restrikciju, zameni sa http://localhost:4200
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent) // 204
			return
		}
		next.ServeHTTP(w, r)
	})
}

func dbNameFromMongoURI(mongoURI string) string {
	u, err := url.Parse(mongoURI)
	if err != nil {
		return ""
	}
	p := strings.Trim(u.Path, "/")
	return p
}

// ✅ token + email helpers (magic link reset)

func generateToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Ako SMTP nije podešen, samo loguje link (za demo).
func sendResetEmail(toEmail, resetLink string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")

	if host == "" || port == "" || from == "" {
		log.Printf("(DEV) reset link for %s: %s", toEmail, resetLink)
		return nil
	}

	addr := fmt.Sprintf("%s:%s", host, port)

	subject := "Music Platform - reset lozinke"
	body := fmt.Sprintf(
		"Zdravo,\n\nKliknite na link da resetujete lozinku (vazi kratko):\n%s\n\nAko niste trazili reset, ignorisite ovaj email.\n",
		resetLink,
	)

	msg := []byte("To: " + toEmail + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" + body)

	var auth smtp.Auth
	if user != "" && pass != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}

	return smtp.SendMail(addr, auth, from, []string{toEmail}, msg)
}

// ===== Handlers =====

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "users service is running",
	})
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	req.Username = sanitizeString(req.Username)
	req.FirstName = sanitizeString(req.FirstName)
	req.LastName = sanitizeString(req.LastName)
	req.Email = normalizeEmail(req.Email)

	if !validateUsername(req.Username) {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Korisničko ime mora biti 3-30 karaktera (slova, brojevi, _)"})
		return
	}
	if !validateEmail(req.Email) {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeća email adresa"})
		return
	}
	if !validateName(req.FirstName) || !validateName(req.LastName) {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Ime i prezime moraju biti 2-50 karaktera"})
		return
	}
	ok, msg := validatePassword(req.Password)
	if !ok {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: msg})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	count, err := userCollection.CountDocuments(ctx, bson.M{
		"$or": []bson.M{
			{"username": req.Username},
			{"email": req.Email},
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri proveri korisnika"})
		return
	}
	if count > 0 {
		writeJSON(w, http.StatusConflict, Response{Success: false, Message: "Korisničko ime ili email već postoji"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri obradi lozinke"})
		return
	}

	now := time.Now()
	newUser := User{
		Username:          req.Username,
		Email:             req.Email,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		HashedPassword:    string(hashedPassword),
		Role:              "user",
		PasswordCreatedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
		IsActive:          true,
	}

	res, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri upisu u bazu"})
		return
	}

	newUser.ID = res.InsertedID.(primitive.ObjectID)
	newUser.HashedPassword = ""

	writeJSON(w, http.StatusCreated, Response{
		Success: true,
		Message: "Korisnik uspešno registrovan",
		Data:    newUser,
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	req.Email = normalizeEmail(req.Email)

	if !validateEmail(req.Email) {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeća email adresa"})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	var user User
	err := userCollection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			writeJSON(w, http.StatusUnauthorized, Response{Success: false, Message: "Nevažeći kredencijali"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri prijavi"})
		return
	}

	if !user.IsActive {
		writeJSON(w, http.StatusForbidden, Response{Success: false, Message: "Nalog je deaktiviran"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, Response{Success: false, Message: "Nevažeći kredencijali"})
		return
	}

	user.HashedPassword = ""
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Uspešna prijava",
		Data:    user,
	})
}

func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći ID korisnika"})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	var user User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			writeJSON(w, http.StatusNotFound, Response{Success: false, Message: "Korisnik nije pronađen"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri čitanju korisnika"})
		return
	}

	user.HashedPassword = ""
	writeJSON(w, http.StatusOK, Response{Success: true, Data: user})
}

func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := requestCtx(r)
	defer cancel()

	filter := bson.M{}

	role := strings.TrimSpace(r.URL.Query().Get("role"))
	if role != "" {
		filter["role"] = role
	}

	active := strings.TrimSpace(r.URL.Query().Get("active"))
	if active == "true" {
		filter["isActive"] = true
	} else if active == "false" {
		filter["isActive"] = false
	}

	cur, err := userCollection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri listanju korisnika"})
		return
	}
	defer cur.Close(ctx)

	var users []User
	if err := cur.All(ctx, &users); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri obradi rezultata"})
		return
	}
	for i := range users {
		users[i].HashedPassword = ""
	}

	writeJSON(w, http.StatusOK, Response{Success: true, Data: users})
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći ID korisnika"})
		return
	}

	var req UpdateUserRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	updateSet := bson.M{"updatedAt": time.Now()}

	if req.FirstName != "" {
		req.FirstName = sanitizeString(req.FirstName)
		if !validateName(req.FirstName) {
			writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Ime mora biti 2-50 karaktera"})
			return
		}
		updateSet["firstName"] = req.FirstName
	}

	if req.LastName != "" {
		req.LastName = sanitizeString(req.LastName)
		if !validateName(req.LastName) {
			writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Prezime mora biti 2-50 karaktera"})
			return
		}
		updateSet["lastName"] = req.LastName
	}

	if req.Email != "" {
		req.Email = normalizeEmail(req.Email)
		if !validateEmail(req.Email) {
			writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeća email adresa"})
			return
		}
		updateSet["email"] = req.Email
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	if email, ok := updateSet["email"].(string); ok && email != "" {
		count, err := userCollection.CountDocuments(ctx, bson.M{
			"email": email,
			"_id":   bson.M{"$ne": objID},
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri proveri email-a"})
			return
		}
		if count > 0 {
			writeJSON(w, http.StatusConflict, Response{Success: false, Message: "Email već postoji"})
			return
		}
	}

	res, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateSet})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri ažuriranju"})
		return
	}
	if res.MatchedCount == 0 {
		writeJSON(w, http.StatusNotFound, Response{Success: false, Message: "Korisnik nije pronađen"})
		return
	}

	var updated User
	if err := userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&updated); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri čitanju ažuriranog korisnika"})
		return
	}
	updated.HashedPassword = ""

	writeJSON(w, http.StatusOK, Response{Success: true, Message: "Korisnik uspešno ažuriran", Data: updated})
}

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći ID korisnika"})
		return
	}

	var req ChangePasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	ok, msg := validatePassword(req.NewPassword)
	if !ok {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: msg})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	var user User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			writeJSON(w, http.StatusNotFound, Response{Success: false, Message: "Korisnik nije pronađen"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.OldPassword)); err != nil {
		writeJSON(w, http.StatusUnauthorized, Response{Success: false, Message: "Neispravna stara lozinka"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri obradi lozinke"})
		return
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"hashedPassword":    string(hashed),
			"passwordCreatedAt": time.Now(),
			"updatedAt":         time.Now(),
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri promeni lozinke"})
		return
	}

	writeJSON(w, http.StatusOK, Response{Success: true, Message: "Lozinka uspešno promenjena"})
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći ID korisnika"})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	res, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"isActive":  false,
			"updatedAt": time.Now(),
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri brisanju"})
		return
	}
	if res.MatchedCount == 0 {
		writeJSON(w, http.StatusNotFound, Response{Success: false, Message: "Korisnik nije pronađen"})
		return
	}

	writeJSON(w, http.StatusOK, Response{Success: true, Message: "Korisnik uspešno obrisan"})
}

// ✅ Forgot password (magic link) handler
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	email := normalizeEmail(req.Email)
	// Anti-enumeration: uvek vraćamo istu poruku
	okMsg := "Ako nalog postoji, link je poslat na email."

	if !validateEmail(email) {
		writeJSON(w, http.StatusOK, Response{Success: true, Message: okMsg})
		return
	}

	ctx, cancel := requestCtx(r)
	defer cancel()

	var user User
	err := userCollection.FindOne(ctx, bson.M{"email": email, "isActive": true}).Decode(&user)
	if err != nil {
		// ne odajemo da li postoji
		writeJSON(w, http.StatusOK, Response{Success: true, Message: okMsg})
		return
	}

	rawToken, err := generateToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri generisanju tokena"})
		return
	}

	expires := time.Now().Add(15 * time.Minute)
	tokenHash := sha256Hex(rawToken)

	_, err = userCollection.UpdateOne(ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{
			"resetTokenHash":      tokenHash,
			"resetTokenExpiresAt": expires,
			"updatedAt":           time.Now(),
		}},
	)
	if err != nil {
		// i dalje ne odajemo detalje korisniku
		writeJSON(w, http.StatusOK, Response{Success: true, Message: okMsg})
		return
	}

	frontendBase := os.Getenv("FRONTEND_BASE_URL")
	if frontendBase == "" {
		frontendBase = "http://localhost:4200"
	}
	frontendBase = strings.TrimRight(frontendBase, "/")

	// reset-password.html treba da postoji u frontendu
	resetLink := fmt.Sprintf("%s/reset-password.html#token=%s", frontendBase, rawToken)

	if err := sendResetEmail(email, resetLink); err != nil {
		// ne failujemo korisniku; logujemo za debug
		log.Println("smtp error:", err)
	}

	writeJSON(w, http.StatusOK, Response{Success: true, Message: okMsg})
}

// ✅ Reset password handler
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći JSON format"})
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" || len(token) > 200 {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: "Nevažeći token"})
		return
	}

	ok, msg := validatePassword(req.NewPassword)
	if !ok {
		writeJSON(w, http.StatusBadRequest, Response{Success: false, Message: msg})
		return
	}

	tokenHash := sha256Hex(token)
	now := time.Now()

	ctx, cancel := requestCtx(r)
	defer cancel()

	var user User
	err := userCollection.FindOne(ctx, bson.M{
		"resetTokenHash":      tokenHash,
		"resetTokenExpiresAt": bson.M{"$gt": now},
		"isActive":            true,
	}).Decode(&user)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, Response{Success: false, Message: "Token je nevažeći ili je istekao"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri obradi lozinke"})
		return
	}

	_, err = userCollection.UpdateOne(ctx,
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"hashedPassword":    string(hashed),
				"passwordCreatedAt": now,
				"updatedAt":         now,
			},
			"$unset": bson.M{
				"resetTokenHash":      "",
				"resetTokenExpiresAt": "",
			},
		},
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{Success: false, Message: "Greška pri resetovanju lozinke"})
		return
	}

	writeJSON(w, http.StatusOK, Response{Success: true, Message: "Lozinka je uspešno resetovana"})
}

// ===== main =====

func main() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017/users_db"
	}

	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = dbNameFromMongoURI(mongoURI)
	}
	if dbName == "" {
		dbName = "users_db"
	}

	// connect
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("failed to connect to MongoDB: ", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("failed to ping MongoDB: ", err)
	}

	userCollection = client.Database(dbName).Collection("users")

	// indexes
	indexModels := []mongo.IndexModel{
		{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "resetTokenHash", Value: 1}}},
	}
	if _, err := userCollection.Indexes().CreateMany(ctx, indexModels); err != nil {
		log.Println("warning: failed to create indexes: ", err)
	}

	router := mux.NewRouter()

	// FIX #1: Global OPTIONS preflight handler (bez ovoga browser dobije 404/405 bez CORS headera)
	router.PathPrefix("/").Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent) // 204
	})

	// Base routes
	router.HandleFunc("/health", HealthCheckHandler).Methods("GET")
	router.HandleFunc("/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/login", LoginHandler).Methods("POST")

	// Optional prefixed routes
	router.HandleFunc("/users/health", HealthCheckHandler).Methods("GET")
	router.HandleFunc("/users/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/users/login", LoginHandler).Methods("POST")

	// Resource routes
	router.HandleFunc("/users", GetAllUsersHandler).Methods("GET")
	router.HandleFunc("/users/{id}", GetUserHandler).Methods("GET")
	router.HandleFunc("/users/{id}", UpdateUserHandler).Methods("PUT")
	router.HandleFunc("/users/{id}/password", ChangePasswordHandler).Methods("PUT")
	router.HandleFunc("/users/{id}", DeleteUserHandler).Methods("DELETE")

	// ✅ password reset (magic link)
	router.HandleFunc("/password/forgot", ForgotPasswordHandler).Methods("POST")
	router.HandleFunc("/password/reset", ResetPasswordHandler).Methods("POST", "PUT")
	router.HandleFunc("/users/password/forgot", ForgotPasswordHandler).Methods("POST")
	router.HandleFunc("/users/password/reset", ResetPasswordHandler).Methods("POST", "PUT")

	// FIX #2: mux CORS middleware + tvoj CORS middleware
	router.Use(mux.CORSMethodMiddleware(router))
	router.Use(enableCORS)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("users service listening on :%s (db=%s)", port, dbName)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal("server failed: ", err)
	}
}
