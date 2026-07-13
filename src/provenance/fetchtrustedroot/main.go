// Command fetchtrustedroot fetches the Sigstore public-good trusted_root.json via
// TUF and writes it to the path given as the first argument. It is a throwaway
// developer tool used once to vendor the trust root for offline verification;
// it is not part of the built product.
package main

import (
	"log"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: fetchtrustedroot <output-path>")
	}
	c, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		log.Fatalf("tuf client: %v", err)
	}
	b, err := c.GetTarget("trusted_root.json")
	if err != nil {
		log.Fatalf("get trusted_root.json: %v", err)
	}
	//nolint:gosec // dev-only maintenance tool; output path is a trusted CLI arg
	if err := os.WriteFile(os.Args[1], b, 0o600); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("wrote %d bytes", len(b))
}
