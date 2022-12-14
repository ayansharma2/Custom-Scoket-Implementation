package main

import (
	"os"
	"os/exec"
)

func main() {
	portNo := os.Args[1]

	cmd := exec.Command("lsof -i tcp:" + portNo)
	cmd.Run()
	initSocket(portNo)

}
