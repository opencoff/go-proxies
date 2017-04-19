// log.go - Logging adaptor

package main

	// My logger
import (

    "fmt"
    "time"
    
    L "github.com/opencoff/go-lib/logger"
)

type myLogger struct {
    *L.Logger   // inherit all the other methods

    // URL Log
    ul      *L.Logger
}

func newLogger(dl *L.Logger, ulog string) (*myLogger, error) {

    var ul *L.Logger
    
    if len(ulog) > 0 {
        var err error

        // No prefix and no timestamp or other additional info
        ul, err = L.NewFilelog(ulog, L.LOG_INFO, "", 0)
        if err != nil {
            return nil, fmt.Errorf("can't create URL Log: %s", err)
        }

        // Rotate logs 1 second past midnight and keep last 10 days
        ul.EnableRotation(00, 00, 01, 10)
    }

    return &myLogger{Logger: dl, ul: ul}, nil
}


// Interface implementation of proxy.Logger

/*
func (m *myLogger) Debug(fmt string, args ..interface{}) {
    m.dl.Debug(fmt, args...)
}

func (m *myLogger) Info(fmt string, args ..interface{}) {
    m.dl.Info(fmt, args...)
}

func (m *myLogger) Warn(fmt string, args ..interface{}) {
    m.dl.Warn(fmt, args...)
}


func (m *myLogger) Error(fmt string, args ..interface{}) {
    m.dl.Error(fmt, args...)
}
*/


func (m *myLogger) URL(stat int, url string, nr int64, t0, t1 time.Duration) {
    if m.ul == nil { return }

    d0 := "-"
    d1 := "-"

    if stat == 200 {
        d0 = fmt.Sprintf("%s", t0)
        d1 = fmt.Sprintf("%s", t1)
    }

    now := time.Now().UTC().Format(time.RFC3339)

    m.ul.Info("time=%q url=%q status=\"%d\" bytes=\"%d\" upstream=%q downstream=%q",
                 now, url, stat, nr, d0, d1)
}


