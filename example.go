package main

import (
	"fmt"
	"github.com/andrewhodel/go-ip-ac"
)

func main() {

	var ip_ac = ipac.Ipac

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

	// test if you should warn users from an IP
	var warn = ipac.TestIpWarn(ip_ac, "127.0.0.1")

	// return details for a specific ip address
	var ip_details = ipac.IpDetails(ip_ac, "127.0.0.1")

}

