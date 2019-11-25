package main

import (
	"errors"
	"net"
	"strconv"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
)

var errPrivateIP = errors.New("Private IP")
var errNoSuitableIP = errors.New("No suitable IP")
var errNoAnswer = errors.New("No IP")
var dnsEndpointQs string

func getUsableIP(hostname, portStr string) (*net.TCPAddr, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ipp := net.ParseIP(hostname)
	if ipp != nil {
		if isPrivateIP(ipp) {
			return nil, errPrivateIP
		}
		return &net.TCPAddr{
			IP:   ipp,
			Port: port,
		}, nil
	}
	req := fasthttp.AcquireRequest()
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.SetRequestURI(dnsEndpointQs)
	req.URI().QueryArgs().Set("name", hostname)
	resp := fasthttp.AcquireResponse()
	err = httpClient.DoTimeout(req, resp, httpClientTimeout)
	fasthttp.ReleaseRequest(req)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}
	body, err := getResponseBody(resp)
	fasthttp.ReleaseResponse(resp)
	if err != nil {
		return nil, err
	}
	answers := gjson.GetBytes(body, "Answer")
	if answers.Exists() == false || answers.IsArray() == false {
		return nil, errNoAnswer
	}
	for _, answer := range answers.Array() {
		ip := answer.Get("data").String()
		ipp = net.ParseIP(ip)
		if ipp == nil || isPrivateIP(ipp) {
			continue
		}
		tcpAddr := &net.TCPAddr{
			IP:   ipp,
			Port: port,
		}
		conn, err := net.DialTCP("tcp4", nil, tcpAddr)
		if err == nil {
			conn.Close()
			return tcpAddr, nil
		}
	}
	return nil, errNoSuitableIP
}
