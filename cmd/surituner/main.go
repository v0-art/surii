package main

import (
	"os"

	"surituner/internal/surituner"
)

func main() {
	os.Exit(surituner.RunCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
