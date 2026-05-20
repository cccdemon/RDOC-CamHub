package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/raumdock/rdoc-camhub/internal/devicejwt"
)

// runDeviceJWT implements `camhub devicejwt <subcommand>`. Only `init`
// exists today (M1.B); `rotate` and `inspect` land with the M4 hardening
// pass.
func runDeviceJWT(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: camhub devicejwt init --out <path>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return runDeviceJWTInit(rest)
	default:
		return fmt.Errorf("unknown devicejwt subcommand %q (have: init)", sub)
	}
}

func runDeviceJWTInit(args []string) error {
	fs := flag.NewFlagSet("devicejwt init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "destination path for the ring JSON file")
	force := fs.Bool("force", false, "overwrite an existing file (default: refuse)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		fs.Usage()
		return errors.New("--out is required")
	}

	// Refuse to clobber by default. Generating a fresh ring while one
	// already exists would silently orphan every device JWT in the
	// fleet — far worse than a "file exists" error.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s already exists (pass --force to overwrite)", *out)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", *out, err)
		}
	}

	ring, err := devicejwt.NewRingWithGeneratedKey()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	if err := devicejwt.SaveRingFile(*out, ring); err != nil {
		return fmt.Errorf("save ring: %w", err)
	}
	fmt.Printf("wrote ring with kid=%s to %s\n", ring.CurrentKID, *out)
	return nil
}
