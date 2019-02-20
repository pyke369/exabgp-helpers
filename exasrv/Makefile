#!/bin/sh

simulator: simulator.go exasrv.py exasrv.conf
	go run simulator.go 10.0.2.1 10.0.3.1

run: exasrv.py exasrv.conf
	./exasrv.py exasrv.conf supervise 10.0.2.1

