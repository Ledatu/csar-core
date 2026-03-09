package jwtx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// KeyPair holds a signing key pair with its computed metadata.
type KeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	Algorithm  string // "RS256" or "EdDSA"
	KID        string // hex(SHA256(DER_pubkey)[:8])
	PublicDER  []byte // DER-encoded PKIX public key
}

// GenerateOption configures key generation.
type GenerateOption func(*generateOpts)

type generateOpts struct {
	rsaBits int
}

// WithRSABits sets the RSA key size (default 2048).
func WithRSABits(bits int) GenerateOption {
	return func(o *generateOpts) { o.rsaBits = bits }
}

// GenerateKeyPair generates an in-memory key pair for the given algorithm.
// Supported algorithms: "RS256", "EdDSA".
func GenerateKeyPair(algorithm string, opts ...GenerateOption) (*KeyPair, error) {
	o := &generateOpts{rsaBits: 2048}
	for _, fn := range opts {
		fn(o)
	}

	switch algorithm {
	case "EdDSA":
		return generateEdDSA()
	case "RS256":
		return generateRSA(o.rsaBits)
	default:
		return nil, fmt.Errorf("jwtx: unsupported algorithm %q; supported: RS256, EdDSA", algorithm)
	}
}

// LoadKeyPairFromPEM loads a key pair from PEM-encoded files.
// The algorithm is detected from the key type.
func LoadKeyPairFromPEM(privPath, pubPath string) (*KeyPair, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("jwtx: reading private key: %w", err)
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("jwtx: reading public key: %w", err)
	}

	return ParseKeyPairPEM(privData, pubData)
}

// ParseKeyPairPEM parses a key pair from PEM-encoded bytes.
func ParseKeyPairPEM(privPEM, pubPEM []byte) (*KeyPair, error) {
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, fmt.Errorf("jwtx: no PEM block in private key")
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		return nil, fmt.Errorf("jwtx: no PEM block in public key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtx: parsing private key: %w", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtx: parsing public key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("jwtx: private key does not implement crypto.Signer")
	}

	alg, err := DetectAlgorithm(pubKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: signer,
		PublicKey:  pubKey,
		Algorithm:  alg,
		KID:        ComputeKID(pubBlock.Bytes),
		PublicDER:  pubBlock.Bytes,
	}, nil
}

// MarshalKeyPairPEM encodes a KeyPair as PEM-encoded private and public key bytes.
func MarshalKeyPairPEM(kp *KeyPair) (privPEM, pubPEM []byte, err error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("jwtx: marshalling private key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: kp.PublicDER})
	return privPEM, pubPEM, nil
}

// DetectAlgorithm returns the JWT algorithm name for a given public key type.
func DetectAlgorithm(pub crypto.PublicKey) (string, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("jwtx: unsupported public key type %T", pub)
	}
}

func generateEdDSA() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwtx: generating Ed25519 key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("jwtx: marshalling public key: %w", err)
	}
	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "EdDSA",
		KID:        ComputeKID(pubDER),
		PublicDER:  pubDER,
	}, nil
}

func generateRSA(bits int) (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("jwtx: generating RSA-%d key: %w", bits, err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwtx: marshalling public key: %w", err)
	}
	return &KeyPair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		Algorithm:  "RS256",
		KID:        ComputeKID(pubDER),
		PublicDER:  pubDER,
	}, nil
}
