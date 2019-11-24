package main

import (
	"errors"
	"net"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
)

var errPrivateIP = errors.New("Private IP")
var errNoSuitableIP = errors.New("No suitable IP")
var errNoAnswer = errors.New("No IP")
var dnsEndpointQs string

func getUsableIP(hostname, port string) (string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		if isPrivateIP(ip) {
			return "", errPrivateIP
		}
		return hostname, nil
	}
	req := fasthttp.AcquireRequest()
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.SetRequestURI(dnsEndpointQs)
	req.URI().QueryArgs().Set("name", hostname)
	resp := fasthttp.AcquireResponse()
	err := httpClient.DoTimeout(req, resp, httpClientTimeout)
	fasthttp.ReleaseRequest(req)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return "", err
	}
	body, err := getResponseBody(resp)
	fasthttp.ReleaseResponse(resp)
	if err != nil {
		return "", err
	}
	answers := gjson.GetBytes(body, "Answer")
	if answers.Exists() == false || answers.IsArray() == false {
		return "", errNoAnswer
	}
	for _, answer := range answers.Array() {
		ip := answer.Get("data").String()
		if ipp := net.ParseIP(ip); ipp == nil || isPrivateIP(ipp) {
			continue
		}
		conn, err := fasthttp.DialDualStackTimeout("["+ip+"]:"+port, dialTimeout)
		if err == nil {
			conn.Close()
			return ip, nil
		}
	}
	return "", errNoSuitableIP
}
