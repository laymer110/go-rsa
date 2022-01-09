package gorsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func GetPrivateKey(name string) (ss *RSA, err error) {
	var pp string
	pp, err = os.UserHomeDir()
	if err != nil {
		return
	}
	os.Mkdir(pp+"/.auth-server", 0755)

	pp = fmt.Sprintf("%s/.auth-server/%s.json", pp, name)

	data, bb := ioutil.ReadFile(pp)
	if bb != nil {
		ss = CreateRSA()
		data, _ = json.MarshalIndent(ss, " ", "  ")
		ioutil.WriteFile(pp, data, os.ModePerm)
		return
	}
	return PauseRSA(string(data))
}

func CreateRSA() (ss *RSA) {
	pr, _ := rsa.GenerateKey(rand.Reader, 2048)
	ss = &RSA{PrivateKey: pr, PublicKey: &pr.PublicKey}
	return
}

func PauseRSA(data string) (ss *RSA, err error) {
	var tt RSA
	if err = json.Unmarshal([]byte(data), &tt); err != nil {
		return
	}
	ss = &tt
	return
}

func (r *RSA) EncryptOAEP(v interface{}) (data []byte, err error) {
	buf := bytes.NewBuffer(nil)
	if err = json.NewEncoder(buf).Encode(v); err != nil {
		return
	}
	for {
		temp := make([]byte, 100)
		var pd []byte
		if _, end := buf.Read(temp); end == io.EOF {
			break
		}
		pd, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, r.PublicKey, temp, nil)
		if err != nil {
			return
		}
		data = append(data, pd...)
	}
	return
}

func (r *RSA) DecryptOAEP(data []byte, v interface{}) (err error) {
	var dp []byte
	buf := bytes.NewBuffer(data)
	for {
		temp := make([]byte, 256)
		var pd []byte
		if _, end := buf.Read(temp); end == io.EOF {
			break
		}
		pd, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, r.PrivateKey, temp, nil)
		if err != nil {
			return
		}
		dp = append(dp, pd...)
	}
	err = json.Unmarshal(bytes.TrimRight(dp, "\x00"), v)
	return
}
