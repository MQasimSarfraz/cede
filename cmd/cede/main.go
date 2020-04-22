package main

import (
	"fmt"
	"github.com/MQasimSarfraz/cede/pkg/cede"
	"os"
	"strings"
)

const (
	GetKey      = "get-key"
	GetUsers    = "get-users"
	ImportUsers = "import-users"
)

var commands = []string{GetKey, GetUsers, ImportUsers}

func main() {
	args := os.Args
	mustValidate(args)

	var err error
	switch args[1] {
	case GetKey:
		err = cede.PrintIAMKey(args[2])
	case GetUsers:
		err = cede.PrintIAMUsers()
	case ImportUsers:
		err = cede.ImportUserFromIAM()
	}
	if err != nil {
		logAndExit(err.Error(), 1)
	}
}

func mustValidate(args []string) {
	if len(args) < 2 {
		logAndExit(fmt.Sprintf("missing command must be %s", strings.Join(commands, ", ")), 1)
	}

	var cmd string
	for _, command := range commands {
		if command == args[1] {
			cmd = args[1]
		}
	}

	if cmd == "" {
		logAndExit(fmt.Sprintf("unknown command must be %s", strings.Join(commands, ",")), 1)
	}

	if cmd == GetKey && len(args) < 3 {
		logAndExit("get-key: missing username", 1)
	}
}

func logAndExit(msg string, code int) {
	fmt.Printf("cede: %s\n", msg)
	os.Exit(code)
}
