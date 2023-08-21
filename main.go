package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

func main() {
	h := header{
		Alg: "SHA256",
		Typ: "JWT",
	}

	p := payload{
		Name: "nekogan",
		Pass: "password",
		Mail: "nekogan@mail.ru",
	}

	// key := make([]byte, 5)

	// _, err := rand.Read(key)
	// if err != nil {
	// 	log.Fatalf("Не удалось создать ключи шифрования: %v\n", err)
	// }

	finishkey := "helloworld!" //fmt.Sprintf("%x", key)
	fmt.Printf("Конечный ключ шифрования: %s\n", finishkey)

	hb, err := json.Marshal(h)
	if err != nil {
		log.Fatalf("Конвертация header в json: %v\n", err)
	}

	fmt.Printf("JSON header: %v\n", string(hb))

	pb, err := json.Marshal(p)
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

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"type"`
}

type payload struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
	Mail string `json:"mail"`
}
