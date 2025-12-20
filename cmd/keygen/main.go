package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"sso/internal/lib/keygen"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	var (
		dbPath  string
		appID   int
		appName string
		bits    int
	)

	flag.StringVar(&dbPath, "db", "./storage/sso.db", "Path to SQLite database")
	flag.IntVar(&appID, "app-id", 1, "Application ID")
	flag.StringVar(&appName, "app-name", "Test", "Application name")
	flag.IntVar(&bits, "bits", 2048, "RSA key size in bits (2048 or 4096 recommended)")
	flag.Parse()

	// Generate RSA key pair
	fmt.Printf("Generating %d-bit RSA key pair...\n", bits)
	keyPair, err := keygen.GenerateRSAKeyPair(bits)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Println("Keys generated successfully!")
	fmt.Println("\nNOTE: Private key has been stored in the database and is not printed to stdout for security reasons.")
	fmt.Printf("=== PUBLIC KEY ===\n%s\n", keyPair.PublicKey)

	// Open database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() {
		_ = db.Close()
	}()

	// Insert or update app with generated keys.
	// NOTE: This raw SQL is intentionally coupled to the `apps` table schema defined in the
	// database migrations and storage layer. If the `apps` schema changes (e.g., columns are
	// added, removed, or renamed), this query MUST be updated accordingly to stay in sync.
	// Prefer refactoring this tool in the future to reuse the storage layer's app persistence
	// API instead of duplicating schema knowledge here.
	query := `INSERT INTO apps (id, name, private_key, public_key) 
			  VALUES (?, ?, ?, ?) 
			  ON CONFLICT(id) DO UPDATE SET 
			  	name = excluded.name,
			  	private_key = excluded.private_key,
			  	public_key = excluded.public_key`

	_, err = db.Exec(query, appID, appName, keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to insert/update app: %v", err)
	}

	fmt.Printf("\n✓ App (id=%d, name=%s) successfully added to database with RSA keys\n", appID, appName)
	fmt.Printf("✓ Database path: %s\n", dbPath)
}
