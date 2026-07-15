package main
import "crypto/rand"
func run() { _, _ = rand.Read(make([]byte, 16)) }
