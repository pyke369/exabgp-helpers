package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

var bgp = []string{
	`{"type":"state","neighbor":{"ip":"[PEER]","address":{"local":"127.0.0.1","peer":"[PEER]"},"state":"connected"}}`,
	`{"type":"state","neighbor":{"ip":"[PEER]","address":{"local":"127.0.0.1","peer":"[PEER]"},"state":"up"}}`,
	`{"type":"update","neighbor":{"ip":"[PEER]","address":{"local":"127.0.0.1","peer":"[PEER]"},"message":{"update":{"announce":{"ipv4 unicast":{"[PEER]":{"172.16.0.0/24":{},"192.168.0.0/24":{}}}}}}}}`,
	`{"type":"update","neighbor":{"ip":"[PEER]","address":{"local":"127.0.0.1","peer":"[PEER]"},"message":{"update":{"announce":{"ipv4 unicast":{"[PEER]":[{"nlri":"172.16.0.0/24"},{"nlri":"192.168.0.0/24"}]}}}}}}`,
}

func peer(value string) {
	command := exec.Command("./exasrv.py", "exasrv.conf", "supervise", value)
	if handle, err := command.StdinPipe(); err == nil {
		go func(handle io.WriteCloser, value string) {
			for index := 0; index < len(bgp); index++ {
				time.Sleep(time.Second)
				line := strings.Replace(bgp[index], "[PEER]", value, -1) + "\n"
				handle.Write([]byte(line))
				fmt.Printf("\x1b[34m>>> %s\x1b[0m", line)
			}
			select {}
		}(handle, value)
	}
	if handle, err := command.StdoutPipe(); err == nil {
		go func(handle io.ReadCloser) {
			reader := bufio.NewReader(handle)
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					fmt.Printf("\x1b[36m<<< %s\x1b[0m", line)
				}
			}
		}(handle)
	}
	if handle, err := command.StderrPipe(); err == nil {
		go func(handle io.ReadCloser) {
			reader := bufio.NewReader(handle)
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					fmt.Printf("\x1b[33m<<< %s\x1b[0m", line)
				}
			}
		}(handle)
	}
	command.Run()
}

func main() {
	for index := 1; index < len(os.Args); index++ {
		go peer(os.Args[index])
	}
	select {}
}
