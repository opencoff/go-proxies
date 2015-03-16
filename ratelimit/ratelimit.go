//
// Ratelimiting incoming connections - Small Library
//
// (c) 2013 Sudhi Herle <sudhi-dot-herle-at-gmail-com>
//
// License: GPLv2
//
// Notes:
//  - This is a very simple interface for rate limiting. It
//    implements a token bucket algorithm
//  - Based on Anti Huimaa's very clever token bucket algorithm.
//
// Usage:
//    rl = NewRateLimiter(rate)
//
//    ....
//    if rl.Limit() {
//       drop_connection(conn)
//    }
//
package ratelimit
import "time"

type Ratelimiter struct {

    rate  int    // conn/sec
    last  time.Time  // last time we were polled/asked

    allowance float64
}


// Create new rate limiter that limits at rate/sec
func NewRateLimiter(rate int) (*Ratelimiter, error) {

    r := Ratelimiter{rate:rate, last:time.Now()}

    r.allowance = float64(r.rate)
    return &r, nil
}


// Return true if the current call exceeds the set rate, false
// otherwise
func (r* Ratelimiter) Limit() bool {

    // handle cases where rate in config file is unset - defaulting
    // to "0" (unlimited)
    if r.rate == 0 {
        return false
    }

    rate        := float64(r.rate)
    now         := time.Now()
    elapsed     := now.Sub(r.last)
    r.last       = now
    r.allowance += float64(elapsed) * rate


    // Clamp number of tokens in the bucket. Don't let it get
    // unboundedly large
    if r.allowance > rate {
        r.allowance = rate
    }

    var ret bool

    if r.allowance < 1.0 {
        ret = true
    } else {
        r.allowance -= 1.0
        ret = false
    }

    return ret
}

