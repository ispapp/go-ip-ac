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
	"time"
	"fmt"
	"runtime"
)

type Ip struct {

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

	cmd := exec.Command("./command.sh", s)
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

func init(opts Ipac) (Ipac) {

	// remove existing firewall rules created by go-ip-ac
	if (runtime.GOOS == 'linux') {
		// first flush the goipac chain
		_, _ := comm("sudo iptables -F goipac")
		// then delete the chain
		_, _ := comm("sudo iptables -X goipac")
		// then add the chain
		_, _ := comm("sudo iptables -N goipac")
	}

	var o Ipac
	o.CleanupLoopSeconds = 60
	o.BlockForSeconds = 60 * 60 * 24
	o.BlockIpv6SubnetsGroupDepth = 4
	o.BlockIpv6SubnetsBreach = 40
	o.WarnAfterNewConnections = 80
	o.WarnAfterUnauthedAttempts = 5
	o.BlockAfterNewConnections = 600
	o.BlockAfterUnauthedAttempts = 300
	o.NotifyAfterAbsurdAuthAttempts = 20
	o.Mail = ""
	o.Purge = false

	// set options passed to init as default options
	if (opts.CleanupLoopSeconds != 0) {
		o.CleanupLoopSeconds = opts.CleanupLoopSeconds
	}
	if (opts.BlockForSeconds != 0) {
		o.BlockForSeconds = opts.BlockForSeconds
	}
	if (opts.BlockIpv6SubnetsGroupDepth != 0) {
		o.BlockIpv6SubnetsGroupDepth = opts.BlockIpv6SubnetsGroupDepth
	}
	if (opts.BlockIpv6SubnetsBreach != 0) {
		o.BlockIpv6SubnetsBreach = opts.BlockIpv6SubnetsBreach
	}
	if (opts.WarnAfterNewConnections != 0) {
		o.WarnAfterNewConnections = opts.WarnAfterNewConnections
	}
	if (opts.WarnAfterUnauthedAttempts != 0) {
		o.WarnAfterUnauthedAttempts = opts.WarnAfterUnauthedAttempts
	}
	if (opts.BlockAfterNewConnections != 0) {
		o.BlockAfterNewConnections = opts.BlockAfterNewConnections
	}
	if (opts.BlockAfterUnauthedAttempts != 0) {
		o.BlockAfterUnauthedAttempts = opts.BlockAfterUnauthedAttempts
	}
	if (opts.NotifyAfterAbsurdAuthAttempts != 0) {
		o.NotifyAfterAbsurdAuthAttempts = opts.NotifyAfterAbsurdAuthAttempts
	}
	if (opts.Mail != "") {
		o.Mail = opts.Mail
	}

	o.LastCleanup = time.Now().Unix()
	// run a thread to clean and manage routines
	clean_loop := time.NewTicker(opts.CleanupLoopSeconds * time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case t := <-clean_loop.C:
				fmt.Println("Tick at", t)
			}
		}
	}()

	//clean_loop.Stop()
	//done <- true

	return o

}

func TestIpWarn(o Ipac, addr string) (bool) {
}

func TestIpAllowed(o Ipac, addr string) (bool) {
}

func Purge(o Ipac) {
}

func ModifyAuth(o Ipac, authed int, addr string) {
}
