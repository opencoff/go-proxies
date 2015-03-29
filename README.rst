What is go-socksd?
=================
Go-socksd is a SOCKS5 proxy server written in Go_ and designed for
maximal concurrency.  It is expected to scale well on a modern
multi-processor box. It runs on any platform that is supported
by Go (golang.org).

The server supports a simple JSON config file for its configuration.


Major features
==============
- No authentication (yes, its a feature)
- flexible allow/deny rules for discriminating clients
- multiple listeners - each with their own ACL
- Rate limiting incoming connections (per listening IP)

Access Control Rules
====================
Go-socksd implements a flexible ACL by combination of
allow/deny rules. The rules are evaluated in the following order:

- If explicitly denied, the host is blocked
- If explicitly allowed, the host is allowed
- Explicit denial takes precedence over explicit allow
- Empty allow list is the same as "allow all"

Example of allow/deny combinations
----------------------------------

1. Only allow specific subnets and deny everyone else:

    "allow": [ "192.168.55.0/24", "172.16.10.0/24", "127.0.0.1/8" ],
    "deny": []


2. Allow all except selected subnets:

    "allow": [],
    "deny": [ "192.168.80.0/24", "172.16.5.0/24" ]


3. Expliclty block certain hosts and explicitly allow certain
   subnets and block everyone else:

    "allow": [ "192.168.55.0/24", "172.16.10.0/24", "127.0.0.1/8" ],
    "deny":  [ "192.168.1.1/32", "192.168.80.0/24", "172.16.5.0/24" ]

--
Mon Mar 16 09:56:43 PDT 2015
