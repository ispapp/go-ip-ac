/*
Copyright 2022 Andrew Hodel
	andrewhodel@gmail.com
LICENSE MIT
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package ipac

import (
	"os"
	"os/exec"
	"bytes"
	"time"
	"fmt"
	"runtime"
)

type Ip struct {
	Addr				string
	Authed				bool
	Warn				bool
	Blocked				bool
	LastAccess			int
	LastAuth			int
	UnauthedNewConnections		int
	UnauthedAttempts		int
	AbsurdAuthAttempts		int
}

type Ipv6Subnet struct {

}

type Ipac struct {
	CleanupLoopSeconds		int
	BlockForSeconds			int
	BlockIpv6SubnetsGroupDepth	int
	BlockIpv6SubnetsBreach		int
	WarnAfterNewConnections		int
	WarnAfterUnauthedAttempts	int
	BlockAfterNewConnections	int
	BlockAfterUnauthedAttempts	int
	NotifyAfterAbsurdAuthAttempts	int
	Mail				string
	Purge				bool
	LastCleanup			int
	NextEmailBlockedIps		[]string
	NextEmailAbsurdIps		[]string
	Ips				[]Ip
	Ipv6Subnets			[]Ipv6Subnet
	TotalCount			int
	BlockedCount			int
	WarnCount			int
	BlockedSubnetCount		int
}

func comm(s string) (string, string) {

	// the command.sh file is required
	var module_directory = os.Getenv("HOME") + "/go/src/github.com/andrewhodel/go-ip-ac/"

	cmd := exec.Command(module_directory + "command.sh", s)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	_ = cmd.Run()

	if (len(stderr.String()) > 0) {
		fmt.Printf("comm() stderr for `%s`\n\t%s\n", s, stderr.String())
	}

	return out.String(), stderr.String()

}

func Init(o *Ipac) {

	// remove existing firewall rules created by go-ip-ac
	if (runtime.GOOS == "linux") {
		// first flush the goipac chain
		comm("sudo iptables -F goipac")
		// then delete the chain
		comm("sudo iptables -X goipac")
		// then add the chain
		comm("sudo iptables -N goipac")
	}

	// set options passed to init as default options
	if (o.CleanupLoopSeconds == 0) {
		o.CleanupLoopSeconds = 60
	}
	if (o.BlockForSeconds == 0) {
		o.BlockForSeconds = 60 * 60 * 24
	}
	if (o.BlockIpv6SubnetsGroupDepth == 0) {
		o.BlockIpv6SubnetsGroupDepth = 4
	}
	if (o.BlockIpv6SubnetsBreach == 0) {
		o.BlockIpv6SubnetsBreach = 40
	}
	if (o.WarnAfterNewConnections == 0) {
		o.WarnAfterNewConnections = 80
	}
	if (o.WarnAfterUnauthedAttempts == 0) {
		o.WarnAfterUnauthedAttempts = 5
	}
	if (o.BlockAfterNewConnections == 0) {
		o.BlockAfterNewConnections = 600
	}
	if (o.BlockAfterUnauthedAttempts == 0) {
		o.BlockAfterUnauthedAttempts = 300
	}
	if (o.NotifyAfterAbsurdAuthAttempts == 0) {
		o.NotifyAfterAbsurdAuthAttempts = 20
	}
	o.Purge = false

	//fmt.Printf("default options: %+v\n", o)

	o.LastCleanup = int(time.Now().Unix())

	loop_ticker := time.NewTicker(time.Duration(o.CleanupLoopSeconds) * time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case t := <-loop_ticker.C:
				//_ = t
				//fmt.Printf("ipac at %s\n", t)
				//fmt.Println(o.Ips)

				// consider the time since the last interval
				var seconds_since_last_cleanup = int(time.Now().Unix()) - o.LastCleanup

				var expire_older_than = o.BlockForSeconds - seconds_since_last_cleanup

				var ctotal = 0
				var cblocked = 0
				var cwarn = 0
				// IPv6 var cblocked_subnet = 0

				if (o.Purge == true) {
					// remove the ip
					o.Ips = nil
					continue
				}

				// clear expired ips
				for i := range o.Ips {

					var entry = o.Ips[i]

					var age_of_ip = int(time.Now().Unix()) - entry.LastAccess

					if (age_of_ip > expire_older_than) {

						// unblock the ip at the OS level
						modify_ip_block_os(false, entry)

						// delete the ip
						copy(o.Ips[i:], o.Ips[i+1:]) // Shift a[i+1:] left one index.
						o.Ips = o.Ips[:len(o.Ips)-1]

					} else {

						// this ip was not deleted, count it
						ctotal += 1
						if (entry.Blocked == true) {
							cblocked += 1
						}
						if (entry.Warn == true) {
							cwarn += 1
						}

					}

				}

				// update the ipac object
				o.TotalCount = ctotal
				o.BlockedCount = cblocked
				o.WarnCount = cwarn

				// IPv6

				if (o.Purge == true) {
					// reset to false
					o.Purge = false
				}

				if (o.Mail != "") {

					// send notifications via email

				}

				// update the last cleanup
				o.LastCleanup = int(time.Now().Unix())

			}
		}
	}()

	//loop_ticker.Stop()
	//done <- true

}

func modify_ip_block_os(block bool, i Ip) {

	// block or unblock the ip at the OS level

	if (block == true) {

		// block the ip address
		if (runtime.GOOS == "linux") {
			comm("sudo iptables -I goipac -s " + i.Addr + " -j DROP")
		}

	} else {

		// unblock the ip address
		if (runtime.GOOS == "linux") {
			comm("sudo iptables -D goipac -s " + i.Addr + " -j DROP")
		}

	}

}

func IpDetails(o *Ipac, addr string) (Ip) {

	var i Ip

	for l := range o.Ips {
		if (o.Ips[l].Addr == addr) {
			i = o.Ips[l]
			break
		}
	}

	return i

}

func TestIpWarn(o *Ipac, addr string) (bool) {

	return IpDetails(o, addr).Warn

}

func TestIpAllowed(o *Ipac, addr string) (bool) {

	// always ran at the start of any request
	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true is the connection is allowed

	// get the ip entry
	var entry = IpDetails(o, addr)

	// set the last access time of the ip
	entry.LastAccess = int(time.Now().Unix())

	if (entry.Addr == addr) {

		// a matching ip address has been found

		if (entry.Authed == false) {
			// increment the number of unauthed connections from this ip
			entry.UnauthedNewConnections += 1
		}

		// warn this ip address if required
		if (entry.UnauthedNewConnections >= o.WarnAfterNewConnections && entry.Warn == false) {
			// made too many unauthed connections
			entry.Warn = true
		} else if (entry.UnauthedAttempts >= o.WarnAfterUnauthedAttempts && entry.Warn == false) {
			// made too many unauthed attempts
			entry.Warn = true
		}

		// block this ip address if it has made too many unauthed connections
		// or invalid authorization attempts
		if ((entry.UnauthedNewConnections >= o.BlockAfterNewConnections || entry.UnauthedAttempts >= o.BlockAfterUnauthedAttempts) && entry.Blocked == false) {

			// set the ip address to be blocked
			entry.Blocked = true

			// block this ip at the OS level
			modify_ip_block_os(true, entry)

			if (o.Mail != "") {

				// add to next email
				o.NextEmailBlockedIps = append(o.NextEmailBlockedIps, entry.Addr)

			}

			// IPv6

		} else if (entry.AbsurdAuthAttempts == o.NotifyAfterAbsurdAuthAttempts) {

			// too many auth attempts while the IP has an authenticated session, send an email

			if (o.Mail != "") {

				// add to next email
				o.NextEmailAbsurdIps = append(o.NextEmailAbsurdIps, entry.Addr)

			}

		}

		// update the o.Ips table
		for l := range o.Ips {
			if (o.Ips[l].Addr == addr) {
				o.Ips[l] = entry
				break
			}
		}

	} else {

		// this ip address is new
		entry.Addr = addr
		o.Ips = append(o.Ips, entry)
		//fmt.Println("ipac.TestIpAllowed, new ip added", len(o.Ips), entry)

	}

	if (entry.Blocked == true) {
		return false
	} else {
		return true
	}

}

func Purge(o *Ipac) {
	// clear all ips
	o.Purge = true
}

func ModifyAuth(o *Ipac, authed int, addr string) {

	if (o.Purge == true) {
		// do not allow modification while purging
		return
	}

	// get the ip entry
	var entry = IpDetails(o, addr)

	var now = int(time.Now().Unix())

	if (entry.Authed == true && authed == 2) {

		// an IP address is authorized but invalid authorizations are happening from the IP
		// perhaps someone else at the location is abusing the authed IP address and trying to guess
		// logins or logout the valid user
		// as node-ip-ac will not deauth an IP without specific instruction to do so
		//
		// modify_auth() should be passed undefined as the authed argument when there is a valid logout
		//
		// increment absurd_auth_attempts
		// to notify the admin and allow the valid user to continue normally

		entry.AbsurdAuthAttempts += 1

	} else if (now - entry.LastAccess > o.BlockForSeconds || authed == 2) {

		// authorized or expired
		// reset the object keys
		// this removes the requirement for waiting until the next cleanup iteration
		// as the whole functionality may be executed during that time
		// and an authorized attempt must reset that possibility

		entry.UnauthedAttempts = 0
		entry.UnauthedNewConnections = 0
		entry.AbsurdAuthAttempts = 0
		entry.Blocked = false
		entry.Warn = false

		if (authed == 2) {
			entry.Authed = true
		}

	} else if (authed == 1) {

		// not authorized or expired

		// increment the invalid authorization attempts counter for this IP address
		entry.UnauthedAttempts += 1

	} else if (authed == 0) {

		// valid logout
		entry.Authed = false

	}

	// set the last auth time of the ip
	entry.LastAuth = now

	// update the o.Ips table
	for l := range o.Ips {
		if (o.Ips[l].Addr == addr) {
			o.Ips[l] = entry
			break
		}
	}

	return

}
