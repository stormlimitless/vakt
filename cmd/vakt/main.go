package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("vakt", version)
		return
	}
	fmt.Fprintln(os.Stderr, "vakt: not implemented yet")
	os.Exit(1)
}
