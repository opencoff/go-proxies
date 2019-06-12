What is this?
=============
A simple implementation of HTTP and SOCKSv5 proxy servers in golang.
The proxy is expected to scale well on a modern multi-processor box.
It runs on any platform that is supported by Go.

Building the servers
---------------------
You need a reasonably new Golang toolchain (1.8+). And the ``go``
executable needs to be in your path. Then run::

    make


The Makefile is exceedingly simple; it invokes::

    ./build


``build`` is the primary script responsible for building ``goproxy``.
It places the binary in TARGET specific directory. e.g., for linux-amd64,
the binaries will be in ``./bin/linux-amd64``; and OS X, it will be in
``./bin/darwin-amd64`` and so on.

You can cross-compile by passing appropriate architecture names to
the script. e.g., to build on host OS X for openbsd-amd64::

    ./build --arch=openbsd-amd64 

You can build a statically linked executable (with no other runtime dependency)::

    ./build -s

The script also has other options. To see them::

    ./build --help


Usage
-----
The server takes a YAML config file as its sole command line argument. The server
does not fork itself into the background. If you need that capability, explore your
platform's init toolchain (e.g., ``start-stop-daemon``).

The server can run in debug mode::

    ./bin/linux-amd64/goproxy -d etc/goproxy.conf


In debug mode, the logs are sent to STDOUT and the debug level is set to DEBUG
(i.e., verbose).

In the absence of the ``-d`` flag, the default log level is INFO.

Config File
-----------
The server config file is a YAML v2 document. It has a section for HTTP proxy and a
separate section for SOCKSv5 proxy. An example is below::

    # Log file; can be one of:
    #  - Absolute path
    #  - SYSLOG
    #  - STDOUT
    #  - STDERR
    #log: /tmp/goproxy.log
    log: STDOUT

    # Logging level - "DEBUG", "INFO", "WARN", "ERROR"
    loglevel: DEBUG

    # Path to URL Log and response codes
    #urllog:

    # drop privileges as soon as listeners are setup to the uid/gid below.
    # Only meaningful if go-proxy is started as root.
    uid: nobody
    gid: nobody

    # Listeners
    http:
        -
            listen: 127.0.0.1:8080

            # if you want this listener to use a specific outbound IP, then set that
            # here
            #bind:

            # ACL
            allow: [127.0.0.1/8, 11.0.1.0/24, 11.0.2.0/24]
            deny: []

            # limit to N reqs/sec globally and M requests per-host
            ratelimit:
                global: 2000
                perhost: 30


    socks:
        -
            listen: 127.0.0.1:2080
            #bind:
            allow: [127.0.0.1/8, 11.0.1.0/24, 11.0.2.0/24]
            deny: []
            # limit to N reqs/sec globally
            ratelimit:
                global: 2000
                perhost: 30



Major features
--------------
- No authentication (yes, its a feature)
- flexible allow/deny rules for discriminating clients
- multiple listeners - each with their own ACL
- Rate limiting incoming connections (global and per-host)

Access Control Rules
--------------------
Go-socksd implements a flexible ACL by combination of
allow/deny rules. The rules are evaluated in the following order:

- If explicitly denied, the host is blocked
- If explicitly allowed, the host is allowed
- Explicit denial takes precedence over explicit allow
- Empty allow list is the same as "allow all"

Example of allow/deny combinations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Only allow specific subnets and deny everyone else:

    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ],
    deny: []


2. Allow all except selected subnets:

    allow: [],
    deny: [ 192.168.80.0/24", 172.16.5.0/24 ]


3. Expliclty block certain hosts and explicitly allow certain
   subnets and block everyone else:

    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ],
    deny:  [ 192.168.1.1/32, 192.168.80.0/24, 172.16.5.0/24 ]


Development Notes
=================
If you are a developer, the notes here will be useful for you:

* We use go module support; so you will need go 1.10+ for this to work.

* The build script ``build`` is a shell script to build the program.
  It does two very important things:
    * Puts the binary in an OS/Arch specific directory
    * Injects a git version-tag into the final binary ("linker resolved symbol")

* Example config files is in the ``etc/goproxy.conf`` directory.


Redirect Error
--------------
If you are receiving some error like::

  gopkg.in/h2non/bimg.v1: Cloning and checking out v1.0.6..
  error: RPC failed; HTTP 301 curl 22 The requested URL returned error: 301
  fatal: The remote end hung up unexpectedly

It is because something in git around version 2.11.1 stops following redirects.
A popular repository of golang packages uses this. To workaround, try::

  git config --global http.https://gopkg.in.followRedirects true

.. vim: ft=rst:sw=4:ts=4:expandtab:tw=84:
