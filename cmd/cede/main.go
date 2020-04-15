package main

import (
	"fmt"
	"github.com/MQasimSarfraz/cede/pkg/sshkey"
	"os"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("cede: no username provided")
		os.Exit(1)
	}

	err := sshkey.Execute(args[1])
	if err != nil {
		fmt.Printf("cede: %s\n", err)
		os.Exit(1)
	}
}
