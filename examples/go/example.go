package main
import ("crypto/tls"; "net/http"; "os/exec")
func unsafe(command string) { exec.Command("sh", "-c", command) }
var insecure = &tls.Config{InsecureSkipVerify: true}
var safe = &http.Client{Timeout: 5}
