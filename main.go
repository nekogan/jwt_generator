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
	pa.Name = n
	pa.Pass = p
	pa.Mail = m
}

func main() {

	// router := httprouter.New()
	// router.GET("/", Index)

	// log.Fatal(http.ListenAndServe(":8080", router))

	h := header{
		Alg: "SHA256",
		Typ: "JWT",
	}

	var pl payload
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

	fmt.Printf("TOKEN: %v", token)
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
	fmt.Fprint(w, "Welcome!\n")
}
