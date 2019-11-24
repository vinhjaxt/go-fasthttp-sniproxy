#!/usr/bin/env sh
export GOOS=linux
export GOARCH=386
go build
zip go-fasthttp-sniproxy-linux-386.zip ca.pem domains-certs.json domains.txt domains-regex.txt go-fasthttp-sniproxy

export GOOS=linux
export GOARCH=amd64
go build
zip go-fasthttp-sniproxy-linux-amd64.zip ca.pem domains-certs.json domains.txt domains-regex.txt go-fasthttp-sniproxy

export GOOS=windows
export GOARCH=386
go build
zip go-fasthttp-sniproxy-win32.zip ca.pem domains-certs.json domains.txt domains-regex.txt go-fasthttp-sniproxy.exe

export GOOS=windows
export GOARCH=amd64
go build
zip go-fasthttp-sniproxy-win64.zip ca.pem domains-certs.json domains.txt domains-regex.txt go-fasthttp-sniproxy.exe
