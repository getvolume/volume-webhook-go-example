package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Process the webhook data as needed
	fmt.Println(string(body))

	authorisationHeader := r.Header.Get("Authorization")

	// Splitting the header value by spaces
	authorisationHeaderValue := strings.Split(authorisationHeader, " ")

	// Get the last word
	var signature string
	if len(authorisationHeaderValue) > 0 {
		signature = authorisationHeaderValue[len(authorisationHeaderValue)-1]
	}

	validationResult := validateData(string(body), signature)
	fmt.Println(validationResult)

	w.WriteHeader(http.StatusOK)
	// Convert validationResult to JSON
	responseData, err := json.Marshal(validationResult)
	if err != nil {
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}

	// Set content type to JSON and return the validationResult as the response
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseData)
}

type ValidationResponse struct {
	IsValid bool
	Errors  []string
}

func validateData(payload string, signature string) ValidationResponse {
	var errors []string

	verification, err := verifySignature(signature, payload)
	if err != nil || !verification {
		errors = append(errors, "Signature not valid")
	}

	var data map[string]string
	err = json.Unmarshal([]byte(payload), &data)

	paymentID, idOk := data["paymentId"]
	if !idOk || paymentID == "" {
		errors = append(errors, `Invalid or missing "paymentId" field`)
	}

	paymentStatus, statusOk := data["paymentStatus"]
	if !statusOk || paymentStatus == "" {
		errors = append(errors, `Invalid or missing "paymentStatus" field`)
	}

	// ... validate other payments according to business logic

	if len(errors) > 0 {
		return ValidationResponse{
			IsValid: false,
			Errors:  errors,
		}
	}

	return ValidationResponse{
		IsValid: true,
	}
}

func fetchPublicKey() (*rsa.PublicKey, error) {
	pemUrl := os.Getenv("PEM_URL")
	resp, err := http.Get(pemUrl)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Add prefix and postfix to the fetched data
	fullPEM := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", body)
	block, _ := pem.Decode([]byte(fullPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return rsaPub, nil
}

func verifySignature(signature string, payload string) (bool, error) {
	pubKey, err := fetchPublicKey()
	if err != nil {
		return false, err
	}

	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(payload))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], decodedSig)
	if err != nil {
		return false, err
	}

	return true, nil
}

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	http.HandleFunc("/webhook", handleWebhook)
	http.ListenAndServe(":8080", nil)
}
