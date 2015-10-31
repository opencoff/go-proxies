//
// Socks5 proxy in Go
// (c) 2013 Sudhi Herle <sudhi-dot-herle-at-gmail-com>
//
// License: GPLv2
//
// - supports IPv4 and IPv6
// - supports TCP and UDP
// - ACL for allowed/denied hosts. ACL rules are simple:
//    * if explicitly denied, block the host
//    * if explictly allowed, allow the host
//    * explicit denial takes precedence over allow
//    * empty allow is same as "allow all"

package main

import (
    "net"
    "fmt"
    "io"
    "os"
    "errors"
    "strings"
    "syscall"
    "encoding/hex"
    "encoding/json"
    "flag"
    "time"
    "sync/atomic"
    "os/signal"
    "runtime"
)

import L "./logger"
import "./ratelimit"

var debug = flag.Bool("debug", false, "Run in debug mode")


var Ngo         int64
var N_lhs       int64
var N_rhs       int64


type Methods struct {
    ver, nmethods uint8
    methods []uint8
}


// URL Logger - log URLs and bytes transferred
// - Writes are queued into a channel; a go routine picks off messages
//   from the channel and writes to disk.
// - Does synchronous writes to the underlying file.
type urllog struct {
    fd *os.File
    n  int
    logch chan string
}


func NewURLLogger(fn string) (ul *urllog, err error) {

    // append or truncate??
    flags := os.O_WRONLY|os.O_CREATE|os.O_SYNC
    flags |= os.O_APPEND
    fd, err := os.OpenFile(fn, flags, 0644)
    if err != nil {
        return nil, err
    }

    ul = &urllog{fd: fd}
    ul.logch = make(chan string)

    // Now fork a go routine to do synchronous log writes
    go func(l *urllog) {
        for s := range l.logch {
            l.fd.Write([]byte(s))
        }
    }(ul)

    return ul, nil
}


// URL timestamp is always logged as UTC - to keep it unambiguous
func (l *urllog) LogURL(ls, rs, url string, l2r, r2l int64) {
    now        := time.Now().UTC()
    yy, mm, dd := now.Date()
    hh, m, ss  := now.Clock()
    us         := int(now.Nanosecond() / 1e3)

    s := fmt.Sprintf("%s %04d-%02d-%02d %02d:%02d:%02d.%06d %s [%s] %d %d",
                        ls, yy, mm, dd, hh, m, ss, us, url, rs, l2r, r2l)

    s += "\n"

    l.logch <- s
}


// Socks Proxy config
// A listenr and its ACL
type socksProxy struct {
    listen  net.Listener // Listener
    bind    net.Addr     // address to bind to when connect to remote
    log     *L.Logger    // Shortcut to logger
    ulog    *urllog      // URL Logger
    cfg     configEntry  // The listener config + ACL

    rl      *ratelimit.Ratelimiter
}


// Make a new proxy server
func newProxy(cfg configEntry, log *L.Logger, ul *urllog) (px *socksProxy, err error) {
    ln, err := net.Listen("tcp", cfg.Listen)
    if err != nil {
        return nil, err
    }

    var addr net.Addr

    if len(cfg.Bind) > 0 {
        log.Info("Binding to %s ..\n", cfg.Bind)
        addr, err = net.ResolveTCPAddr("tcp", cfg.Bind)

        if err != nil {
            return nil, err
        }
    }

    px = &socksProxy{listen: ln, bind: addr, log: log, ulog: ul, cfg: cfg}

    rl, err := ratelimit.NewRateLimiter(cfg.Rlimit)
    px.rl = rl
    return
}



// ACL for incoming connection
func (px *socksProxy) AclOK(conn net.Conn) bool {
    cfg := px.cfg
    h, ok  := conn.RemoteAddr().(*net.TCPAddr)
    if !ok {
        die("%s Can't get TCPAddr from Conn object?!", conn.RemoteAddr().String())
    }

    for _, n := range cfg.Deny {
        if n.Contains(h.IP) {
            return false
        }
    }

    if len(cfg.Allow) == 0 {
        return true
    }

    for _, n := range cfg.Allow {
        if n.Contains(h.IP) {
            return true
        }
    }

    return false
}

// start the proxy
// Caller is expected to kick this off as a go-routine
// XXX Need to rate limit - do we do it per source IP?
// XXX Also need a global limit on total concurrent connections?
func (px *socksProxy) start() {
    ln   := px.listen
    log  := px.log

    nerr := 0

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Err("Failed to accept new connection on %s: %s", ln.Addr().String(), err)
            log.Err("   %d active goroutines, %d LHS %d RHS", Ngo, N_lhs, N_rhs)
            nerr += 1
            if nerr > 5 {
                log.Err("Too many consecutive accept failures! Aborting...")
                die("Aborting gosocksd due to too many failures!")
            }
            continue
        }

        // Reset - as soon as things begin to work
        nerr = 0

        rem := conn.RemoteAddr().String()

        log.Debug("Accepted connection from %s", rem)

        // Check ACL
        if !px.AclOK(conn) {
            conn.Close()
            log.Debug("Denied %s due to ACL", rem)
            continue
        }

        // Ratelimit
        if px.rl.Limit() {
            conn.Close()
            log.Debug("Ratelimited %s", rem)
            continue
        }

        // Fork off a handler for this new connection
        go px.Proxy(conn)
    }
}


type retval struct {
    err error
    n   int64
}

// goroutine to handle a proxy request from 'lhs'
func (px *socksProxy) Proxy(lhs net.Conn) {
    atomic.AddInt64(&N_lhs, 1);
    atomic.AddInt64(&Ngo, 1)
    defer func() {
        atomic.AddInt64(&Ngo, -11)
    }()
    defer func() {
        atomic.AddInt64(&N_lhs, -1);
        //ss := lhs.RemoteAddr().String()
        //px.log.Info("Closing LHS connecction from %s; %d gor, %d/%d open", ss, Ngo, N_lhs, N_rhs)
        lhs.Close()
    }()


    // We expect to get some bytes within 10 seconds.
    lhs.SetReadDeadline(deadLine(10000))

    _, err := px.readMethods(lhs)

    if err != nil {
        return
    }

    log := px.log

    // Hard coded response: "We have no need for auth"
    buf := make([]byte, 2)
    buf[0] = 5
    buf[1] = 0
    lhs.Write(buf)

    // Now we expect to read URL and connect
    rhs, s, err := px.doConnect(lhs)
    if err != nil {
        return
    }
    atomic.AddInt64(&N_rhs, 1);

    defer func() {
        atomic.AddInt64(&N_rhs, -1)
        //ss := rhs.RemoteAddr().String()
        //px.log.Info("Closing RHS connecction from %s; %d gor, %d/%d open", ss, Ngo, N_lhs, N_rhs)
        rhs.Close()
    }()


    // Set read and write deadlines.
    // XXX In general any socket connection must complete its I/O within
    //     10 minutes.
    //
    /*
    tout, _ := time.ParseDuration("3m")
    //tout, _ := time.ParseDuration("10m")

    dl := time.Now().Add(tout)
    lhs.SetDeadline(dl)
    rhs.SetDeadline(dl)
    */


    ls := lhs.RemoteAddr().String()
    rs := rhs.RemoteAddr().String()

    // Fork a go-routine to do I/O in one direction
    rv := make(chan retval, 1)
    go serv(lhs, rhs, rv)

    // Do the other direction of I/O inline
    l2r, err := netcopy(rhs, lhs)

    r := <-rv
    if r.err != nil || err != nil {
        var x string

        if r.err != nil {
            x += fmt.Sprintf("   %s -> %s: %s\n", rs, ls, r.err)
        }
        if err != nil {
            x += fmt.Sprintf("   %s -> %s: %s\n", ls, rs, err)
        }

        log.Err("%s-%s IO Relay returned error:\n%s", ls, rs, x)
    }

    // XXX Log only successful URLs ?
    if px.ulog != nil  {
        px.ulog.LogURL(ls, rs, s, l2r, r.n)
    }
}

// normalize certain types of error as benign
func normalize_err(e error) error {
    switch {
    case e.(net.Error).Timeout():
        e = nil
    case e == syscall.EPIPE:
        e = nil
    }

    return e
}

// Calculate deadLine relative to current time for 'n' milliseconds
func deadLine(nms int) time.Time {
    to := time.Duration(nms) * time.Millisecond
    dl := time.Now().Add(to)
    return dl
}


// Read from 'r' and write to 'w'
// Return number of bytes written
func netcopy(w net.Conn, r net.Conn) (n int64, err error) {

    buf := make([]byte, 16 * 1024)
    n    = 0

    for {
        r.SetReadDeadline(deadLine(25000))
        nr, er := r.Read(buf)
        if nr == 0 {
            break
        } else if nr > 0 {
            i := 0
            for nr > 0 {
                nw, ew := w.Write(buf[i:nr])
                if ew != nil {
                    ew = normalize_err(ew)
                    return n, ew
                }

                nr -= nw
                i  += nw
                n  += int64(nw)
            }
        }

        if er == io.EOF {
            t := r.(*net.TCPConn)
            t.CloseRead()
            break
        } else if er != nil {
            er = normalize_err(er)
            return n, er
        }
    }

    return n, nil
}


// go routine to read from 'r' and write to 'w'.
// The return values are sent back in the channel 'retval'
func serv(w net.Conn, r net.Conn, rv chan<- retval) {
    atomic.AddInt64(&Ngo, 1)
    defer func() {
        atomic.AddInt64(&Ngo, -1)
    }()

    n, err := netcopy(w, r)
    rv  <- retval{err, n}
    close(rv)
}





// Read the advertised methods from the client and respond
func (px *socksProxy) readMethods(conn net.Conn) (m Methods, err error) {
    rem := conn.RemoteAddr().String()
    b := make([]byte, 300)
    n, err := conn.Read(b)
    if err != nil && err != io.EOF {
        px.log.Err("%s Unable to read version info: %s", rem, err)
        return
    }

    if n < 2 {
        px.log.Err("%s Insufficient data while reading version: Saw only %d bytes\n",
                   rem, n)
        err = errors.New("Insufficient data")
        return
    }

    m.ver      = b[0]
    m.nmethods = b[1]

    if n-2 < int(m.nmethods) {
        px.log.Err("%s Insufficient data while reading methods: Saw %d, want %d\n",
                   rem, n-2, m.nmethods)
        err = errors.New("Insufficient data")
    }

    px.log.Debug("%s Methods: %d bytes [%d tot auth meth]\n%s\n", rem, n, int(m.nmethods),
                  hex.Dump(b[0:n]))

    m.methods  = b[2:2+int(m.nmethods)]

    return
}


// Read the connect request and return a successful connection to
// the other side
func (px *socksProxy) doConnect(lhs net.Conn) (rhs net.Conn, s string, err error) {
    ls  := lhs.RemoteAddr().String()

    buf := make([]byte, 256)
    log := px.log

    n, err := lhs.Read(buf)
    if err != nil {
        if err != io.EOF {
            log.Err("%s Unable to read version info: %s", ls, err)
        }
        return
    }


    log.Debug("%s Connect: %d bytes\n%s\n", ls, n, hex.Dump(buf[0:n]))


    // Packet Format:
    // field 1: [0] Version# (must be 0x5)
    // field 2: [1] command code:
    //          0x1: TCP Conn
    //          0x2: TCP Port
    //          0x3: UDP Conn
    // field 3: [2] 0x0 (reserved)
    // field 4: [3] addr type:
    //          0x1: IPv4 (MSB)
    //          0x3: FQDN
    //          0x4: IPv6
    // field 5: dest address: one of:
    //          - 4 bytes of IPv4 address
    //          - 16 bytes of IPv6 address
    //          - 1 byte len + N bytes of domain name
    // field 6: [2] port number in network byte order
    //

    if n < 7 {
        log.Err("%s Insufficient data while reading connect: Saw %d, want 7\n",
                   ls, n)
        err = errors.New("Insufficient data")
        return
    }

    var t string
    var i int


    switch buf[3] {
    case 0x1:
        if n-4 < 4 {
            log.Err("%s Insufficient data for IPv4 addr: saw %d, want 4\n",
                       ls, n-4)
            err = errors.New("Insufficient data")
            return
        }
        s += fmt.Sprintf("%d",  buf[4])
        s += fmt.Sprintf(".%d", buf[5])
        s += fmt.Sprintf(".%d", buf[6])
        s += fmt.Sprintf(".%d", buf[7])

    case 0x3:
        m := int(buf[4])
        if n-4 < m {
            log.Err("%s Insufficient data for domain: saw %d, want %d\n",
                       ls, n-4, m)
            err = errors.New("Insufficient data")
            return
        }

        for i = 0; i < m; i++ {
            s += fmt.Sprintf("%c", buf[i+5])
        }

    case 0x4:
        m := 16
        if n-4 < m {
            log.Err("%s Insufficient data for IPv6 addr: saw %d, want 16\n",
                       ls, n-4)
            err = errors.New("Insufficient data")
            return
        }
        s = fmt.Sprintf("[%02x", buf[5])
        for i = 1; i < m; i++ {
            s += fmt.Sprintf(":%02x", buf[i+5])
        }
        s += "]"
    }


    var port uint16 = uint16(buf[n-2]) << 8 + uint16(buf[n-1])

    s += fmt.Sprintf(":%d", port)


    switch buf[1] {
    case 1:
        t = "tcp"
    case 2: // bind
    case 3:
        t = "udp"
    }


    log.Debug("Connecting to %s ..\n", s)


    tout := time.Duration(px.cfg.Conn_tout) * time.Second
    if tout <= 0 {
        tout, _ = time.ParseDuration("4s")
    }
    d := &net.Dialer{LocalAddr: px.bind, Timeout: tout}



    rhs, err = d.Dial(t, s)
    if err != nil {
        log.Err("%s failed to connect to %s: %s", ls, s, err)
        buf[1] = 4
        lhs.Write(buf[:n])
        return
    }

    buf[1] = 0
    lhs.Write(buf[:n])

    log.Debug("%s connected to %s [%s]", ls, s, rhs.RemoteAddr().String())

    //log.Info("%s CONNECT %s %s\n", ls, s, rhs.RemoteAddr().String())


    return rhs, s, nil
}



//
// socks5d config file details
//

type subnet struct {
    net.IPNet
}


// individual config entry
type configEntry struct {
    Listen  string      `json:"listen"`

    // Optional source to bind to
    Bind    string      `json:"bind"`

    // Optional ratelimit in conn/sec
    Rlimit  int         `json:"ratelimit"`

    // Timeout in seconds for outbound connect requests
    Conn_tout  int      `json:"connect_timeout"`

    // Timeout in seconds for IO activity
    IO_tout    int      `json:"io_timeout"`

    Allow   []subnet      `json:"allow"`
    Deny    []subnet      `json:"deny"`
}


// List of config entries
type configFile struct {
    Logging     string      `json:"log"`
    LogLevel    string      `json:"loglevel"`

    // If this is non-null, log URLs + timestamp to this file
    URLLog      string      `json:"urllog"`

    // socket for monitoring internals of this daemon
    // XXX Think of using gmx
    Monitor     string      `json:"monitor"`

    // If this is non-null, enable HTTP server on this address
    //HTTPServer  string      `json:"http"`

    // Auth info for the admin view
    //HTTPAdmin   string      `json:"adminuser"`
    //HTTPPasswd  string      `json:"adminpassword"`

    // XXX Some timeouts in the future:
    // - DNS timeout
    // - connect timeout
    // - i/o timeout
    //

    // list of listeners and their own ACL
    Cfg     []configEntry   `json:"proxy"`
}

// Custom unmarshaler for IPNet
func (ipn *subnet) UnmarshalJSON(b []byte) error  {
    var s string

    // First unpack the bytes as a string. We then parse the string
    // as a CIDR
    err := json.Unmarshal(b, &s)

    _, net, err := net.ParseCIDR(s)
    if err == nil {
        ipn.IP   = net.IP
        ipn.Mask = net.Mask
    }
    return err
}



// parse and read a config file
func ReadConfig(cfgfile string) (cfg *configFile, err error) {
    fd, err := os.Open(cfgfile); if err != nil {
        return nil, errors.New(fmt.Sprintf("Can't open config file %s: %s\n", cfgfile, err))
    }

    d  := json.NewDecoder(fd)
    cfg = &configFile{}
    err = d.Decode(cfg); if err != nil {
        return nil, errors.New(fmt.Sprintf("Can't parse config file %s: %s\n", cfgfile, err))
    }

    fd.Close()

    return
}


// -- main --



func warn(format string, a ...interface{}) {
    s := fmt.Sprintf(format, a...)
    n := len(s)
    if n > 0 && s[n-1] != '\n' {
        s += "\n"
    }
    os.Stderr.WriteString(s)
}


func die(format string, a ...interface{}) {
    warn(format, a...)
    os.Exit(1)
}

func main() {

    usage := fmt.Sprintf("%s [options] config-file", os.Args[0])

    flag.Usage = func() {
        fmt.Printf("gosocksd - A simple socks5 server\n")
        fmt.Printf("Usage: %s\n", usage)
        flag.PrintDefaults()
    }

    flag.Parse()

    args := flag.Args()
    if len(args) == 0 {
        die("No config file specified.\nUsage: %s\n", usage)
    }

    cfgfile := args[0]
    var logflags int = L.Ldate|L.Ltime|L.Lshortfile|L.Lmicroseconds
    var err error
    var cfg *configFile

    cfg, err = ReadConfig(cfgfile)

    if err != nil {
        die("Can't read config file %s: %s", cfgfile, err)
    }

    var prio L.Priority = L.LOG_DEBUG

    if !*debug {
        var ok bool
        lvl := strings.ToUpper(cfg.LogLevel)
        prio, ok = L.PrioName[lvl]
        if !ok {
            die("Unknown log level %s", lvl)
        }
    }


    log, err := L.NewLogger(cfg.Logging, prio, "socksd", logflags)
    if err != nil {
        die("Can't create logger: %s", err)
    }

    log.Info("gosocksd starting up (logging at %s)...",
              L.PrioString[log.Prio()])

    var ulog *urllog

    if len(cfg.URLLog) > 0 {
        ulog, err = NewURLLogger(cfg.URLLog)
        if err != nil {
            die("Can't create URL logger (%s): %s", cfg.URLLog, err)
        }
        log.Info("writing URL logs to %s", cfg.URLLog)
    }

    // maxout concurrency
    runtime.GOMAXPROCS(runtime.NumCPU())

    // XXX Create a GMX instance here with the socket we find in the
    // config file.  What to do if the socket path is not specified?
    // Use a default one?

    // Now create a new proxy instance for each listenr in the
    // config file
    for _, c := range cfg.Cfg {
        px, err := newProxy(c, log, ulog)
        if err != nil {
            die("Can't start proxy on %s: %s", c.Listen, err)
        }

        go px.start()
    }


    // Setup signal handlers
    sigchan := make(chan os.Signal, 4)
    signal.Notify(sigchan,
                    syscall.SIGTERM, syscall.SIGKILL,
                    syscall.SIGINT, syscall.SIGHUP)

    signal.Ignore(syscall.SIGPIPE, syscall.SIGFPE)


    // Now wait for signals to arrive
    for {
        s := <-sigchan
        t := s.(syscall.Signal)
        log.Info("Caught signal %d; Terminating ..\n", int(t))
        os.Exit(0)
    }


    // TODO:
    // =====
    // o Async DNS handling
    // o timeout handling:
    //     - remote connect
    //     - I/O timeouts and closing sockets
    //
    // o readability improvements
    //
}

// EOF
