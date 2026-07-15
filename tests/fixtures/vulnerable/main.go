package main
import "os/exec"
func run(input string) { exec.Command("sh", "-c", input) }
var token = mathrand.Int()
