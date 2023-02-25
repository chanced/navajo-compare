package main

import (
	"encoding/base64"
	"flag"
	"io"
	"log"
	"os"
	"strings"
)

// for clarity
type Primitive = string

const (
	MAC       Primitive = "MAC"
	AEAD      Primitive = "AEAD"
	DAEAD     Primitive = "DAEAD"
	HPKE      Primitive = "HPKE"
	HKDF      Primitive = "HKDF"
	Signature Primitive = "Signature"
	Agreement Primitive = "Agreement"
)

func main() {
	log.SetFlags(0)
	var (
		pr string
		a  string
		n  string
		k  string
	)
	flag.StringVar(&pr, "primitive", "", "Primitive")
	flag.StringVar(&a, "algorithm", "", "Algorithm")
	flag.StringVar(&n, "nonce", "", "Nonce")
	flag.StringVar(&k, "key", "", "Key")
	flag.Parse()
	var sp string
	args := flag.Args()[1:]
	for _, ap := range args {
		sp += " " + ap
	}

	if pr == "" {
		log.Fatal("missing primitive")
	}

	if a == "" {
		log.Fatal("missing algorithm")
	}
	if !isKnown(a) {
		log.Fatalf("unknown algorithm: %s", a)
	}
	if isIgnored(a) {
		log.Printf("ignored algorithm: %s", a)
		os.Exit(0)
	}
	nb, err := base64.StdEncoding.DecodeString(n)
	if err != nil {
		log.Fatalf("invalid nonce: %s", err)
	}
	kb, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		log.Fatalf("invalid key: %s", err)
	}
	var pb []byte
	if strings.TrimSpace(sp) == "" {
		pb, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("invalid input: %s", err)
		}
	} else {
		pb, err = base64.StdEncoding.DecodeString(sp)
		if err != nil {
			log.Fatalf("invalid input: %s", err)
		}
	}

	switch pr {
	case "MAC":
		handleMAC(a, kb, pb)
	case "AEAD":
		handleAEAD(a, nb, kb, pb)
	case "DAEAD":
		handleDAEAD(a, nb, kb, pb)
	case "HPKE":
		handleHPKE(a, kb, pb)
	case "HKDF":
		handleHKDF(a, kb, pb)
	case "Signature":
		handleSignature(a, kb, pb)
	case "Agreement":
		handleAgreement(a, kb, pb)
	default:
		log.Fatalf("Unknown primitive: %s", pr)
	}
}
