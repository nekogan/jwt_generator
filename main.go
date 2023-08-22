package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"type"`
}

type payload struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
	Mail string `json:"mail"`
}

func (pa *payload) createPayload(n, p, m string) {
	if len(n) < 3 || len(p) < 3 || len(m) < 3 {
		log.Fatal("Не корректные данные")
	}
	pa.Name = n
	pa.Pass = p
	pa.Mail = m
}

func main() {
	router := httprouter.New()
	router.POST("/registration", Index)
	log.Fatal(http.ListenAndServe(":8080", router))
}

func createSecret() string {
	key := make([]byte, 5)

	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Не удалось создать ключи шифрования: %v\n", err)
	}
	return fmt.Sprintf("%x", key)
}

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var pl payload
	err := json.NewDecoder(r.Body).Decode(&pl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := createToken(pl)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	jsonResp, err := json.Marshal(token)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

func createToken(pl payload) string {
	h := header{
		Alg: "SHA256",
		Typ: "JWT",
	}

	pl.createPayload("nekogan", "pass", "mail")

	fmt.Printf("Конечный ключ шифрования: %s\n", createSecret())

	hb, err := json.Marshal(h)
	if err != nil {
		log.Fatalf("Конвертация header в json: %v\n", err)
	}

	fmt.Printf("JSON header: %v\n", string(hb))

	pb, err := json.Marshal(pl)
	if err != nil {
		log.Fatalf("Конвертация header в json: %v\n", err)
	}

	fmt.Printf("JSON payload: %v\n", string(pb))

	unsignedToken := base64.StdEncoding.EncodeToString(hb) + "." + base64.StdEncoding.EncodeToString(pb)

	fmt.Printf("unsignedToken: %v\n", unsignedToken)

	sha := sha256.New()
	sha.Write([]byte(unsignedToken))
	bs := sha.Sum(nil)

	token := unsignedToken + "." + fmt.Sprintf("%x", bs)

	log.Printf("TOKEN: %v\n", token)

	return token
}
