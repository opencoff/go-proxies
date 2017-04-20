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
// We inherit everything from L.Logger and add only this new method


func (m *myLogger) URL(stat int, url string, nr int64, t0, t1 time.Duration) {
    if m.ul == nil { return }

    d0 := "-"
    d1 := "-"

    if stat == 200 {
        d0 = format(t0)
        d1 = format(t1)
    }

    now := time.Now().UTC().Format(time.RFC3339)

    m.ul.Info("time=%q url=%q status=\"%d\" bytes=\"%d\" upstream=%q downstream=%q",
                 now, url, stat, nr, d0, d1)
}


func format(t time.Duration) string {
    u0     := t.Nanoseconds() / 1000
    ma, mf := u0 / 1000, u0 % 1000

    if ma == 0 {
        return fmt.Sprintf("%3.3d us", mf)
    }

    return fmt.Sprintf("%d.%3.3d ms", ma, mf)
}
