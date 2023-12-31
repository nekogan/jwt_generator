package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"type"`
}

func CreatePayload(body string) (pl map[string]string, err error) {
	err = json.Unmarshal([]byte(body), &pl)
	if err != nil {
		fmt.Printf("Ошибка при конвертации body в json: %v\n", err)
		return nil, err
	}
	return pl, nil
}

func main() {
	router := httprouter.New()
	router.GET("/", Index)
	log.Fatal(http.ListenAndServe(":8080", router))
}

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}

	pl, err := CreatePayload(string(b))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Ошибка: %v\n", err)))
		return
	}

	token, err := CreateToken(pl)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Ошибка: %v\n", err)))
		return
	}

	bj, err := json.MarshalIndent(token, "", "	")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Ошибка: %v\n", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bj)
}

// Возвращает 'string' случайный ключ для шифрования из 10 символов
func createSecret() []byte {
	key := make([]byte, 64)

	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Не удалось создать ключи шифрования: %v\n", err)
	}

	return key
}

type token struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

func CreateToken(pl map[string]string) (token, error) {
	h := header{
		Alg: "SHA512",
		Typ: "JWT",
	}

	key := createSecret()

	hb, err := json.Marshal(h)
	if err != nil {
		log.Fatalf("Конвертация header в json: %v\n", err)
		return token{}, err
	}

	pb, err := json.Marshal(pl)
	if err != nil {
		log.Fatalf("Конвертация payload в json: %v\n", err)
		return token{}, err
	}

	unsignedToken := base64.RawStdEncoding.EncodeToString(hb) + "." + base64.RawStdEncoding.EncodeToString(pb)

	sha := hmac.New(sha256.New, key)
	sha.Write([]byte(unsignedToken))
	sh := hex.EncodeToString(sha.Sum(nil))

	tokenStr := unsignedToken + "." + string(sh)

	return token{
		Token:  tokenStr,
		Secret: base64.RawStdEncoding.EncodeToString(key),
	}, nil
}
