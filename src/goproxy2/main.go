// main.go -- main() for http proxy & socks5 proxy
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"runtime"
	"strings"
	"syscall"
	"io/ioutil"
	"os/signal"
	"runtime/pprof"

	flag "github.com/ogier/pflag"
	yaml "gopkg.in/yaml.v2"

	L "github.com/opencoff/go-lib/logger"
)

// This will be filled in by "build"
var RepoVersion string	  = "UNDEFINED"
var Buildtime   string	  = "UNDEFINED"
var ProductVersion string = "UNDEFINED"

// Number of minutes of profile data to capture
// XXX Where should this be set? Config file??
const PROFILE_MINS = 30

// Interface for all proxies
type Proxy interface {
	Start()
	Stop()
}


// List of config entries
type Conf struct {
	Logging          string         `yaml:"log"`
	LogLevel         string         `yaml:"loglevel"`
	URLlog			 string			`yaml:"urllog"`
	Http  			[]ListenConf
	Socks 			[]ListenConf
}

type ListenConf struct {
	Listen		string		`yaml:"listen"`
	Bind		string		`yaml:"bind"`
	Allow		[]subnet	`yaml:"allow"`
	Deny		[]subnet	`yaml:"deny"`

	// Global and Per-Host rate limit
	Ratelimit	RateLimit	`yaml:"ratelimit"`
}

type RateLimit struct {
	Global		int			`yaml:"global"`
	PerHost		int			`yaml:"perhost"`
}


// An IP/Subnet
type subnet struct {
    net.IPNet
}

// Custom unmarshaler for IPNet
func (ipn *subnet) UnmarshalYAML(unm func(v interface{}) error) error  {
    var s string

    // First unpack the bytes as a string. We then parse the string
    // as a CIDR
	err := unm(&s)
	if err != nil { return err }

    _, net, err := net.ParseCIDR(s)
    if err == nil {
        ipn.IP   = net.IP
        ipn.Mask = net.Mask
    }
    return err
}


// Parse config file in YAML format and return
func ReadYAML(fn string) (*Conf, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("Can't read config file %s: %s", fn, err)
	}

	var cfg Conf
	err = yaml.Unmarshal(yml, &cfg)
	if err != nil {
		return nil, fmt.Errorf("Can't parse config file %s: %s", fn, err)
	}

	return &cfg, nil
}

func main() {
	// maxout concurrency
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Make sure any files we create are readable ONLY by us
	syscall.Umask(0077)

	debugFlag := flag.BoolP("debug", "d", false, "Run in debug mode")
	verFlag := flag.BoolP("version", "v", false, "Show version info and quit")

	usage := fmt.Sprintf("%s [options] config-file", os.Args[0])

	flag.Usage = func() {
		fmt.Printf("goproxy - A simple HTTP/SOCKSv5 Proxy\nUsage: %s\n", usage)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *verFlag {
		fmt.Printf("goproxy - %s [%s; %s]\n", ProductVersion, RepoVersion, Buildtime)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		die("No config file!\nUsage: %s", usage)
	}


	cfgfile  := args[0]
	cfg, err := ReadYAML(cfgfile)
	if err != nil {
		die("Can't read config file %s: %s", cfgfile, err)
	}

	// We want microsecond timestamps and debug logs to have short
	// filenames
	const logflags int = L.Ldate | L.Ltime | L.Lshortfile | L.Lmicroseconds
	prio := L.LOG_DEBUG
	logf := "STDOUT"

	if !*debugFlag {
		var ok bool

		lvl := strings.ToUpper(cfg.LogLevel)
		prio, ok = L.PrioName[lvl]
		if !ok {
			die("Unknown log level %s", lvl)
		}

		logf = cfg.Logging
	}

	log, err := L.NewLogger(logf, prio, "goproxy", logflags)
	if err != nil {
		die("Can't create logger: %s", err)
	}

	err = log.EnableRotation(00, 01, 00, 7)
	if err != nil {
		warn("Can't enable log rotation: %s", err)
	}

    var ulog *L.Logger

    if len(cfg.URLlog) > 0 {
        ulog, err := L.NewFilelog(cfg.URLlog, L.LOG_INFO, "", 0)
        if err != nil {
            die("Can't create URL logger: %s", err)
        }

        ulog.EnableRotation(00, 00, 01, 01)
    }


	log.Info("goproxy - %s [%s - built on %s] starting up (logging at %s)...",
		ProductVersion, RepoVersion, Buildtime, L.PrioString[log.Prio()])

	var srv []Proxy

	for _, v := range cfg.Http {
		if len(v.Listen) == 0 {
			die("http listen address is empty?")
		}
		s, err := NewHTTPProxy(&v, log, ulog)
		if err != nil {
			die("Can't create http listener on %s: %s", v, err)
		}

		srv = append(srv, s)
		s.Start()
	}

	for _, v := range cfg.Socks {
		if len(v.Listen) == 0 {
			die("SOCKSv5 listen address is empty?")
		}
		s, err := NewSocksProxy(&v, log, ulog)
		if err != nil {
			die("Can't create socks listener on %s: %s", v, err)
		}

		srv = append(srv, s)
		s.Start()
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
		break
	}

	for _, s := range srv {
		s.Stop()
	}

	log.Info("Shutdown complete!")

	// Finally, close the logging subsystem
	log.Close()
	os.Exit(0)
}

// Profiler
func initProfilers(log *L.Logger, dbdir string) {
	cpuf := fmt.Sprintf("%s/cpu.cprof", dbdir)
	memf := fmt.Sprintf("%s/mem.mprof", dbdir)

	cfd, err := os.OpenFile(cpuf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0600)
	if err != nil {
		die("Can't create %s: %s", cpuf, err)
	}

	mfd, err := os.OpenFile(memf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0600)
	if err != nil {
		die("Can't create %s: %s", memf, err)
	}

	log.Info("Starting CPU & Mem Profiler (first %d mins of execution)..", PROFILE_MINS)

	pprof.StartCPUProfile(cfd)
	time.AfterFunc(PROFILE_MINS*time.Minute, func() {
		pprof.StopCPUProfile()
		cfd.Close()
		log.Info("Ending CPU profiler..")
	})

	time.AfterFunc(PROFILE_MINS*time.Minute, func() {
		pprof.WriteHeapProfile(mfd)
		mfd.Close()
		log.Info("Ending Mem profiler..")
	})
}

// vim: ft=go:sw=4:ts=4:noexpandtab:tw=78:
