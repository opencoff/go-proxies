// main.go -- main() for http proxy
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	flag "github.com/ogier/pflag"
	yaml "gopkg.in/yaml.v2"

	// My logger
	L "github.com/opencoff/go-lib/logger"
)

// This will be filled in by "build"
var RepoVersion string	  = "UNDEFINED"
var Buildtime   string	  = "UNDEFINED"
var ProductVersion string = "UNDEFINED"

// Number of minutes of profile data to capture
// XXX Where should this be set? Config file??
const PROFILE_MINS = 30


// List of config entries
type Conf struct {
	Logging          string         `yaml:"log"`
	LogLevel         string         `yaml:"loglevel"`
	URLlog			 string			`yaml:"urllog"`
	Listen			[]string		`yaml:"listen"`
}

type ListenConf struct {
	Addr		string
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
		fmt.Printf("httproxy - A simple HTTP Proxy\nUsage: %s\n", usage)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *verFlag {
		fmt.Printf("httproxy - %s [%s; %s]\n", ProductVersion, RepoVersion, Buildtime)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		die("Usage: %s", usage)
	}


	cfgfile := args[0]

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

	dlog, err := L.NewLogger(logf, prio, "httproxy", logflags)
	if err != nil {
		die("Can't create logger: %s", err)
	}

	log, err := newLogger(dlog, cfg.URLlog)
	if err != nil {
		die("Can't create my-logger: %s", err)
	}

	log.Info("%s -- httproxy - %s [%s - built on %s] starting up (logging at %s)...",
		time.Now().UTC().Format(time.RFC822Z), ProductVersion, RepoVersion, Buildtime,
		L.PrioString[log.Prio()])

	// Enable rotation at 00:01:00 (1 min past midnight); keep 7 days worth of logs
	err = log.EnableRotation(00, 01, 00, 7)
	if err != nil {
		warn("Can't enable log rotation: %s", err)
	}

	var srv []*HTTPProxy

	for _, v := range cfg.Listen {
		log.Info("Listening on %s ..", v)
		s, err := NewHTTPProxy(log, v, nil)
		if err != nil {
			die("Can't create listener on %s: %s", v, err)
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
