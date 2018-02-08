// sockss.go - SOCKSv5 Proxy Server
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
    "io"
    "fmt"
    "net"
    "sync"
    "time"
    "errors"
    //"encoding/hex"

    L "github.com/opencoff/go-lib/logger"
    "github.com/opencoff/go-lib/ratelimit"
)




type Proxy struct {
    Dialer  *net.Dialer

    // How frequently do we shove bytes forcibly down the pipe?
    FlushInterval time.Duration

    // If absent, client is denied server connection
    Authenticate    func(cl *Client) (int, error)

    // if present, checks to see if remote connect should be allowed
    // default is to assume that the connection is allowed.
    AllowConnect    func(client net.Addr, remote net.Addr) bool

    // Error log
    ErrorLog    *stdlog.Logger

    // Optional: bind-to address for outgoing connections
    Bind        net.Addr

    // XXX Timeouts
}

// The incoming client and their credentials
type Client struct {
    AuthType    int // 0: none, 1: GSSAPI, 2: username/passwd, rest: reserved

    User        string  // username
    Passwd      string  // password

    Client      net.Addr    // client address
    Server      net.Addr    // server address
}


type Request struct {
    Type        RequestType // Enum
    Network     string      // tcp, udp
    Addr        net.Addr    // destination addr or bin
}


const (
    ReqConnect  = 1,
    ReqBind = 2,
    ReqAssociate = 3,
)

// request response status
const (
    StatusOK = iota,
    StatusServerFailure,
    StatusConnNotAllowed,
    StatusNetUnreachable,
    StatusHostUnreachable,
    StatusConnRefused,
    StatusTTLExpired,
    StatusUnsupportedCommand,
    StatusUnsupportedAddressType,
)

// Well known timeouts
type Timeouts struct {

    // timeout for receiving auth methods request
    AuthTimeout     time.Duration

    // timeout for receiving connect request
    RequestTimeout  time.Duration

    // body I/O deadlines
    ReadTimeout     time.Duration
    WriteTimeout    time.Duration
}

type Server struct {

    // internal objs that make up a server
    pr  *Proxy

    to  Timeouts

    listeners   map[net.Listener]bool
    conn        map[*conn]bool

    // private fields
    done    chan bool
}

// initialize server 's' to work with Proxy 'p'
func NewServer(p *Proxy, to *Timeouts) (*Server, error) {
    s = &Server{
            pr: p,
            to: *to,
            done: make(chan bool),
            listeners: make(map[net.Listener]bool),
            conns: make(map[*conn]bool),
        }


    return s, nil
}

// We only provide one.
func (s *Server) Serve(ln net.Listener) error {

    defer ln.Close()

    var errDelay time.Duration   = 2500 * time.Microsecond
    const maxDelay time.Duration = 1 * time.Second

    ctx := context.Background()
    ctx  = context.WithValue(ctx, "socks5-server", s)

    s.addListener(ln)
    defer s.rmListener(ln)

    for {
        nc, e := ln.Accept()
        if e == nil {
            errDelay = 2500 * time.Microsecond

            c := s.newConn(nc)

            go c.serve(ctx)
            continue
        }

        select {
        case <-s.done:
            return ErrServerClosed
        default:
        }

        // temporary failures, exponential backoff
        if ne, ok := e.(net.Error); ok && ne.Temporary() {
            errDelay *= 2
            if errDelay > maxDelay {
                errDelay = maxDelay
            }
            s.log("socks5-server: temporary accept() error: %v; retrying in %v", e, errDelay)
            time.Sleep(errDelay)
            continue
        }

        // All other errors are sent back to caller
        return e
    }
}



// Gracefully shutdown the server
func (s *Server) Shutdown(ctx context.Context) error {
    // 1. close active listeners
    // 2. close done chan
    // 3. wait for active conns to be closed

    s.mu.Lock()
    s.rmListenersAndCloseLocked()
    close(s.done)
    s.closeActiveConn()

    s.mu.Unlock()

    for {
        // XXX How long to wait for active conns to go away?
        // how will I know

        select {
        case <-ctx.Done():
            return ctx.Err()

        // XXX ??
        }
    }

}


func (s *Server) addListener(ln net.Listener) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.listeners[ln] = true
}


// Only untrack the given listener. don't close it! The caller
func (s *Server) rmListener(ln net.Listener) {
    s.mu.Lock()
    defer s.mu.Unlock()

    delete(s.listeners, ln)
}

// remove and close all listeners
func (s *Server) rmListenersAndCloseLocked() {
    for ln := range s.listeners {
        delete(s.listeners, ln)
        ln.Close()
    }
}



func (s *Server) rmConn(nc net.Conn) {
    s.mu.Lock()
    delete(s.conns, nc)
    s.mu.Unlock()
    nc.Close()
}

// close all active connections
func (s *Server) closeActiveConnLocked() {
}


func (s *Server) newConn(nc net.Conn) *conn {
    c := &conn{
        srv: s,
        c: nc,
        car: nc.RemoteAddr(),
        cal: nc.LocalAddr(),
    }

    s.mu.Lock()
    s.conns[c] = true
    s.mu.Unlock()

    return c
}


type conn struct {
    srv     *Server
    c       net.Conn

    car      net.Addr       // client addr remote 
    cal      net.Addr       // client add local; i.e., the server's listening addr


    // XXX Do we need a chan to unblock the go-routine?
}

// started as a go-routine in Server:Serve()
func (c *conn) serve(ctx context.Context) {

    // XXX do we catch/recover a panic from deep in the call chain
    //     below?


    defer c.close()

    // XXX read the header, auth and do the thing.

    // XXX Dial remote using the supplied dialer

    // XXX defer close the remote end as well

    cpctx, cancel := context.WithCancel(ctx)
    defer cancel()

    // Finally, create a buffered io-copier like the http-proxy.
    // pass cpctx to them - so they know if they are cancelled
    var wg sync.WaitGroup

    wg.Add(2)

    // XXX go routines spun up here

    // wait for both go-routines to end and then  close 'ch'
    cpdone := make(chan bool)
    go func(ch chan bool) {
        wg.Wait()
        close(ch)
    }(cpdone)

    // wait for go-routines to finish or we are asked to shutdown
    for {
        select {
            case <-c.done:
                cancel()    // this should kill the copy go-routines

            case <-cpdone:
                // we are done serving.
                return
            default:
        }
    }
}


func (c *conn) close() {
    c.srv.rmConn(c.c)

    // XXX logging?
}









// SOCKSv5 methods
type Methods struct {
    ver, nmethods uint8
    methods []uint8
}


// Socks Proxy config
// A listenr and its ACL
type socksProxy struct {
    *net.TCPListener

    bind    net.Addr     // address to bind to when connect to remote
    log     *L.Logger    // Shortcut to logger
    ulog    *L.Logger    // URL Logger
    cfg     *ListenConf  // config block

    stop  chan bool
    wg    sync.WaitGroup
    rl      *ratelimit.Ratelimiter
}


// Make a new proxy server
func NewSocksv5Proxy(cfg *ListenConf, log, ulog *L.Logger) (px *socksProxy, err error) {
    la, err := net.ResolveTCPAddr("tcp", cfg.Listen)
    if err != nil {
        die("Can't resolve %s: %s", cfg.Listen, err)
    }

    ln, err := net.ListenTCP("tcp", la)
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

    px = &socksProxy{bind: addr, log: log, ulog: ulog,  cfg: cfg}

    px.TCPListener = ln
    px.stop = make(chan bool)

    rl, err := ratelimit.New(cfg.Ratelimit, 1)
    px.rl = rl

    log.Info("SOCKS listening on %s ..", cfg.Listen)
    return
}


func (px *socksProxy) Start() {
    px.wg.Add(1)
    go func() {
        defer px.wg.Done()
        px.log.Info("Starting SOCKS proxy on %s ..", px.cfg.Listen)
        px.accept()
    }()
}

func (px *socksProxy) Stop() {
    close(px.stop)
    px.wg.Wait()
    px.log.Info("SOCKS proxy on %s shutdown", px.cfg.Listen)
}



// start the proxy
// Caller is expected to kick this off as a go-routine
// XXX Also need a global limit on total concurrent connections?
func (px *socksProxy) accept() {
    ln   := px.TCPListener
    log  := px.log

    la := ln.Addr().String()
    nerr := 0

    for {
        ln.SetDeadline(time.Now().Add(2 * time.Second))
        conn, err := ln.Accept()
        select {
        case _ = <- px.stop:
            if err == nil { conn.Close() }
            return

        default:
        }

        if err != nil {
            if ne, ok := err.(net.Error); ok {
                if ne.Timeout() || ne.Temporary() {
                    continue
                }
            }

            log.Error("Failed to accept new connection on %s: %s", la, err)
            nerr += 1
            if nerr > 5 {
                log.Error("Too many consecutive accept failures! Aborting...")
                die("Aborting gosocksd due to too many failures!")
            }
            continue
        }

        // Ratelimit before anything else we do
        if px.rl.Limit() {
            log.Debug("%s: Ratelimited %s", la, conn.RemoteAddr().String())
            conn.Close()
            continue
        }


        // Reset - as soon as things begin to work
        nerr = 0

        rem := conn.RemoteAddr().String()

        log.Debug("Accepted connection from %s", rem)

        // Check ACL
        if !AclOK(px.cfg, conn) {
            conn.Close()
            log.Debug("Denied %s due to ACL", rem)
            continue
        }

        // Fork off a handler for this new connection
        go px.Proxy(conn)
    }
}


// goroutine to handle a proxy request from 'lhs'
func (px *socksProxy) Proxy(lhs net.Conn) {

    // We expect to get some bytes within 10 seconds.
    //lhs.SetReadDeadline(deadLine(10000))

    _, err := px.readMethods(lhs)

    if err != nil {
        return
    }

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


    lx := lhs.(*net.TCPConn)
    rx := rhs.(*net.TCPConn)

    var w sync.WaitGroup
    
    w.Add(2)
    go px.iocopy(lx, rx, &w)
    go px.iocopy(rx, lx, &w)

    w.Wait()

    if px.ulog != nil  {
        now        := time.Now().UTC()
        yy, mm, dd := now.Date()
        hh, m, ss  := now.Clock()
        us         := int(now.Nanosecond() / 1e3)

        ls := lx.RemoteAddr().String()
        rs := rx.RemoteAddr().String()
        s  := fmt.Sprintf("%s %04d-%02d-%02d %02d:%02d:%02d.%06d %s [%s]",
                            ls, yy, mm, dd, hh, m, ss, us, s, rs)

        px.ulog.Info(s)
    }
}



// Copy from 's' to 'd'
func (px *socksProxy) iocopy(d, s *net.TCPConn, w *sync.WaitGroup) int64 {
    n, err := io.Copy(d, s)
    if err != nil && err != io.EOF && !isReset(err) {
            px.log.Debug("copy from %s to %s: %s",
                        s.RemoteAddr().String(), d.RemoteAddr().String(), err)
    }

    d.CloseWrite()
    s.CloseRead()

    w.Done()
    return n
}


// Read the advertised methods from the client and respond
func (px *socksProxy) readMethods(conn net.Conn) (m Methods, err error) {
    rem := conn.RemoteAddr().String()
    b := make([]byte, 300)
    n, err := conn.Read(b)
    if err != nil && err != io.EOF {
        px.log.Error("%s Unable to read version info: %s", rem, err)
        return
    }

    if n < 2 {
        px.log.Error("%s Insufficient data while reading version: Saw only %d bytes\n",
                   rem, n)
        err = errors.New("Insufficient data")
        return
    }

    m.ver      = b[0]
    m.nmethods = b[1]

    if n-2 < int(m.nmethods) {
        px.log.Error("%s Insufficient data while reading methods: Saw %d, want %d\n",
                   rem, n-2, m.nmethods)
        err = errors.New("Insufficient data")
    }

    //px.log.Debug("%s Methods: %d bytes [%d tot auth meth]\n%s\n", rem, n, int(m.nmethods),
    //            hex.Dump(b[0:n]))

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
            log.Error("%s Unable to read version info: %s", ls, err)
        }
        return
    }


    //log.Debug("%s Connect: %d bytes\n%s\n", ls, n, hex.Dump(buf[0:n]))


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
        log.Error("%s Insufficient data while reading connect: Saw %d, want 7\n",
                   ls, n)
        err = errors.New("Insufficient data")
        return
    }

    var t string
    var i int


    switch buf[3] {
    case 0x1:
        if n-4 < 4 {
            log.Error("%s Insufficient data for IPv4 addr: saw %d, want 4\n",
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
            log.Error("%s Insufficient data for domain: saw %d, want %d\n",
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
            log.Error("%s Insufficient data for IPv6 addr: saw %d, want 16\n",
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


    //log.Debug("Connecting to %s ..\n", s)


    /*
    tout := time.Duration(px.cfg.Conn_tout) * time.Second
    if tout <= 0 {
        tout, _ = time.ParseDuration("4s")
    }
    */
    d := &net.Dialer{LocalAddr: px.bind, Timeout: 5 * time.Second}



    rhs, err = d.Dial(t, s)
    if err != nil {
        log.Error("%s failed to connect to %s: %s", ls, s, err)
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


