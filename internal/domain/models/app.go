package models

type App struct {
	ID         int
	Name       string
	PrivateKey string // RSA private key in PEM format (for signing tokens)
	PublicKey  string // RSA public key in PEM format (for verifying tokens)
}
