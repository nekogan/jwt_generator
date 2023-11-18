// *Генератор JWT*
// Для получения сгенерированного токена необходимо соблюдать строгий формат данных json
// Обычно в body передаётся "полезная нагрузка" в формате json
// Например,
// {
// 	"login":"apple",
// 	"pass":"banana",
// 	"mail": "juice"
// }
// При соблюдении данного формата, в response возвращается полностью сгенерированный JWT
// Не обязательно передавать данные, указанные в примере выше
// Вы так же можете описывать необходимую для Вас полезную нагрузку, добавив, например, время создания токена
// {
// 	"time", "2023-11-11T16:00:00:000"
// }
// Attemption: при увеличении данных в полезной нагрузке, увеличивается и время создания JWT

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

type Payload struct {
	pl map[string]string
}

func (pa *Payload) CreatePayload(body string) {
	if err := json.Unmarshal([]byte(body), &pa.pl); err != nil {
		fmt.Printf("Ошибка при конвертации body в json: %v", err)
	}
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
	var pl Payload
	pl.CreatePayload(string(b))
	token := CreateToken(pl)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	bj, err := json.MarshalIndent(token, "", "	")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprintf(w, "%+v", string(bj))
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

func CreateToken(pl Payload) token {
	h := header{
		Alg: "SHA512",
		Typ: "JWT",
	}

	key := createSecret()

	hb, err := json.Marshal(h)
	if err != nil {
		log.Fatalf("Конвертация header в json: %v\n", err)
	}

	pb, err := json.Marshal(pl.pl)
	if err != nil {
		log.Fatalf("Конвертация payload в json: %v\n", err)
	}

	unsignedToken := base64.RawStdEncoding.EncodeToString(hb) + "." + base64.RawStdEncoding.EncodeToString(pb)

	sha := hmac.New(sha256.New, key)
	sha.Write([]byte(unsignedToken))
	sh := hex.EncodeToString(sha.Sum(nil))

	tokenStr := unsignedToken + "." + string(sh)

	return token{
		Token:  tokenStr,
		Secret: base64.RawStdEncoding.EncodeToString(key),
	}
}
