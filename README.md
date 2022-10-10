## installation

```
GO111MODULE=off go get github.com/andrewhodel/go-ip-ac
```

## usage

In your socket/request/api code

```
```

## default options

Set these in the object {} passed as the first argument to `ipac.Init()` if you want to change the defaults shown here.

```
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.CleanupLoopSeconds = 60

// how many seconds to ban/block entities for
o.BlockForSeconds = 60 * 60 * 24

// maximum depth to classify IPv6 is
// 64 bits of a network prefix and 64 bits of an interface identifier
// 64 bits is 4 groups that are 16 bits each
o.BlockIpv6SubnetsGroupDepth = 4

// the number of IP bans within a subnet group required for a subnet group to be blocked
o.block_ipv6_subnets_breach = 40
// number of lowest level subnets to block
// multiplied by itself for each step back
//
// example values: depth 4 and breach 40
// example ip: 2404:3c00:c140:b3c0:5d43:d92e:7b4f:5d52
//
// 2404* blocked at 40*40*40*40 ips
// 2404:3c00* blocked at 40*40*40 ips
// 2404:3c00:c140* blocked at 40*40 ips
// 2404:3c00:c140:b3c0* blocked at 40 ips

// warn after N unauthorized new connections
// requests from these IP addresses should
// display a denial of service warning for the IP
// in the user interface
o.WarnAfterNewConnections = 80

// block after N unauthorized new connections
o.BlockAfterNewConnections = 600

// block after N invalid authorization attempts
// this prevents login guessing many times from the same IP address
o.BlockAfterUnauthedAttempts = 5

// notify after N absurd auth attempts
// failed authorization attempts after the IP has been authorized
o.NotifyAfterAbsurdAuthAttempts = 20

// set this string to send an email notification regarding
// new IP addresses were banned
// new IP addresses exceeded the absurd_auth_attempts limit
// a new subnet was blocked

// string with smtp credentials
o.Mail = ""
```

## counts

You may want the total counts.

```
// count of IP Addresses that have connected in the last ip_ac.block_for_seconds
ip_ac.TotalCount

// count of IP Addresses that are blocked
ip_ac.BlockedCount

// count of IP Addresses that are warned
ip_ac.WarnCount

// count of subnets that are blocked
ip_ac.BlockedSubnetCount
```

## firewall support

In this module there exists support for `iptables` on Linux.

There is structure for supporting any OS and firewall that Go supports.

There is also structure for supporting API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
