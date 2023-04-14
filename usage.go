package main

import (
	"fmt"

	_ "embed"
)

//go:embed usage.txt
var instructions string

func usage() {
	fmt.Printf("%v", instructions)
}
