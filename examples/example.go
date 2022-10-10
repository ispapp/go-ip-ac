package main

import (
	"github.com/andrewhodel/go-ip-ac"
	"fmt"
)

func main() {

	var opts ipac.Ipac
	var ip_ac = ipac.Init(opts)

	// set authorization status for an IP
	// reset (use this on invalid authorization attempts)
	ipac.ModifyAuth(ip_ac, 0, "127.0.0.1")
	// failed/unauthorized (use this on valid logouts)
	ipac.ModifyAuth(ip_ac, 1, "127.0.0.1")
	// authorized (use this on valid logins)
	ipac.ModifyAuth(ip_ac, 2, "127.0.0.1")

	// test authorization status for an IP
	// this needs to be called every time there is a new IP connection
	var status = ipac.TestIpAllowed(ip_ac, "127.0.0.1")
	fmt.Printf("TestIpAllowed 127.0.0.1: %b\n", status)

	// test if you should warn users from an IP
	var warn = ipac.TestIpWarn(ip_ac, "127.0.0.1")
	fmt.Printf("TestIpWarn 127.0.0.1: %b\n", warn)

	// return details for a specific ip address
	var ip_details = ipac.IpDetails(ip_ac, "127.0.0.1")
	fmt.Printf("IpDetails 127.0.0.1: %+v\n", ip_details)

	select{}

}

