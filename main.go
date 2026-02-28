package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Struktura za korisnika
type User struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	FirstName         string    `json:"first_name"`
	LastName          string    `json:"last_name"`
	HashedPassword    string    `json:"-"`
	PasswordCreatedAt time.Time `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
}

// Registracija request
type RegisterRequest struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

// Login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Response struktura
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var users = make(map[string]*User)

// Validacija jake lozinke
func isStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// Validacija email adrese
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// REGISTRACIJA
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Neispravan format zahteva",
		})
		return
	}

	// Validacija obaveznih polja
	if req.Username == "" || req.Email == "" || req.FirstName == "" ||
		req.LastName == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Sva polja su obavezna (username, email, first_name, last_name, password, confirm_password)",
		})
		return
	}

	// Provera da li korisničko ime već postoji
	if _, exists := users[req.Username]; exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Korisničko ime već postoji",
		})
		return
	}

	// Validacija email adrese
	if !isValidEmail(req.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Email adresa nije validna",
		})
		return
	}

	// Provera da li se lozinke poklapaju
	if req.Password != req.ConfirmPassword {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Lozinke se ne poklapaju",
		})
		return
	}

	// Validacija jake lozinke
	if !isStrongPassword(req.Password) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Lozinka mora imati minimum 8 karaktera, bar jedno veliko slovo, malo slovo, broj i specijalan karakter",
		})
		return
	}

	// Hashiranje lozinke
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Greška prilikom hashiranja lozinke",
		})
		return
	}

	// Kreiranje novog korisnika
	user := &User{
		ID:                fmt.Sprintf("%d", time.Now().Unix()),
		Username:          req.Username,
		Email:             req.Email,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		HashedPassword:    string(hashedPassword),
		PasswordCreatedAt: time.Now(),
		CreatedAt:         time.Now(),
	}

	users[req.Username] = user

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Korisnik uspešno registrovan",
		Data: map[string]interface{}{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"created_at": user.CreatedAt,
		},
	})
}

// PRIJAVA
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Neispravan format zahteva",
		})
		return
	}

	// Validacija obaveznih polja
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Korisničko ime i lozinka su obavezni",
		})
		return
	}

	// Provera da li korisnik postoji
	storedUser, exists := users[req.Username]
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Neispravno korisničko ime ili lozinka",
		})
		return
	}

	// Provera da li je lozinka istekla (60 dana)
	if time.Since(storedUser.PasswordCreatedAt).Hours() > 60*24 {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Lozinka je istekla. Potrebno je resetovati lozinku",
		})
		return
	}

	// Provera lozinke
	err := bcrypt.CompareHashAndPassword([]byte(storedUser.HashedPassword), []byte(req.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Neispravno korisničko ime ili lozinka",
		})
		return
	}

	// Uspešna prijava
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Uspešna prijava",
		Data: map[string]interface{}{
			"id":         storedUser.ID,
			"username":   storedUser.Username,
			"email":      storedUser.Email,
			"first_name": storedUser.FirstName,
			"last_name":  storedUser.LastName,
		},
	})
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")

	fmt.Println("==================================================")
	fmt.Println("🚀 Server pokrenut na portu 8080")
	fmt.Println("==================================================")
	fmt.Println("\n📍 Dostupni endpointi:")
	fmt.Println("  POST http://localhost:8080/register")
	fmt.Println("  POST http://localhost:8080/login")
	fmt.Println()

	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Println("❌ Greška pri pokretanju servera:", err)
	}
}
