#! /usr/bin/env python

from time import time
import time, sys, datetime


class TokenBucket(object):
    """An implementation of the token bucket algorithm.
    
    >>> bucket = TokenBucket(80, 0.5)
    >>> print bucket.consume(10)
    True
    >>> print bucket.consume(90)
    False
    """
    def __init__(self, tokens, fill_rate):
        """tokens is the total tokens in the bucket. fill_rate is the
        rate in tokens/second that the bucket will be refilled."""
        self.capacity = float(tokens)
        self._tokens = float(tokens)
        self.fill_rate = float(fill_rate)
        self.timestamp = time()

    def consume(self, tokens):
        """Consume tokens from the bucket. Returns True if there were
        sufficient tokens otherwise False."""
        if tokens <= self.tokens:
            self._tokens -= tokens
        else:
            return False
        return True

    def get_tokens(self):
        now = time()
        if self._tokens < self.capacity:
            delta = self.fill_rate * (now - self.timestamp)
            self._tokens = min(self.capacity, self._tokens + delta)
        self.timestamp = now
        return self._tokens

    tokens = property(get_tokens)

def test_tokenbucket():
    from time import sleep
    bucket = TokenBucket(80, 1)
    print "tokens =", bucket.tokens
    print "consume(10) =", bucket.consume(10)
    print "consume(10) =", bucket.consume(10)
    sleep(1)
    print "tokens =", bucket.tokens
    sleep(1)
    print "tokens =", bucket.tokens
    print "consume(90) =", bucket.consume(90)
    print "tokens =", bucket.tokens


class simulated_time:
    t = 0

    def __init__(self, ms):
        self.t = ms

    @classmethod
    def elapsed(kls, ms):
        kls.t += ms

    @classmethod
    def now(kls):
        return simulated_time(kls.t)

    def __sub__(self, b):
        """self - b"""

        assert self.t > b.t, "self.sub LHS smaller than RHS"

        ms = self.t - b.t
        s  = ms / 1000
        ms = ms % 1000
        us = ms * 1000
        return datetime.timedelta(0, s, us)

    def __rsub__(self, b):
        """b - self"""

        assert b.t > self.b, "self.sub RHS smaller than LHS"
        ms = b.t - self.t
        s  = ms / 1000
        ms = ms % 1000
        us = ms * 1000
        return datetime.timedelta(0, s, us)

    def __str__(self):
        return "%3d" % self.t

class ratelimiter(object):


    def __init__(self, rate, burst=0, keeper=datetime.datetime):
        """Rate limit to 'rate/s' with a 'burst' over a 100ms interval"""
        self.keeper = keeper
        self.rate   = rate
        self.burst  = burst
        self.last   = keeper.now()
        self.last_b = self.last

        self.allowance       = rate
        self.burst_allowance = burst

        # 100 ms burst interval
        self.burst_interval = datetime.timedelta(0, 0, 100 * 1000)

    def limit(self):
        """Return True if this invocation causes caller to "limit" their activity

        e.g., if used to limit connections, then a True return value should be
        used to drop connections.
        """
        cur      = self.keeper.now()
        d        = cur - self.last
        elapsed  = d.total_seconds()
        self.last = cur

        self.allowance += elapsed * self.rate

        # Clamp the number of tokens in this interval. Don't let the
        # bucket grow out of bound.
        if self.allowance > self.rate:
            self.allowance = self.rate

        print "-- elapsed: %d -- allowance: %4.2f -- " % (elapsed, self.allowance)

        if self.allowance < 1.0:
            ret = True
        else:
            self.allowance -= 1.0
            ret = False


        return ret

    def limit_burst(self):
        """Return True if this invocation causes caller to "limit" their activity

        e.g., if used to limit connections, then a True return value should be
        used to drop connections.
        """

        cur      = self.keeper.now()
        d        = cur - self.last
        bd       = cur - self.last_b
        elapsed  = d.total_seconds()
        self.last = cur

        if bd > self.burst_interval:
            self.burst_allowance = self.burst
            self.last_b = cur
            print "-- %s/%s -- burst-reset %d --" % (cur, bd, self.burst_allowance)
        else:
            self.burst_allowance -= 1

            # We allow this burst to go through.
            if self.burst_allowance >= 0:
                print "-- %s/%s -- allow burst %d --" % (cur, bd, self.burst_allowance)
                return False
            else:
                print "-- %s/%s -- burst-exceeded %d --" % (cur, bd, self.burst_allowance)
                return True

        self.allowance += elapsed * self.rate

        if self.allowance > self.rate:
            self.allowance = self.rate


        if self.allowance < 1.0:
            return True

        self.allowance -= 1.0
        return False




def test_rl(fd):

    # First line is rate limit params
    v = fd.readline().strip().split()
    rate, burst = int(v[0]), int(v[1])

    r = ratelimiter(rate, burst, simulated_time)

    tests = []
    for line in fd:
        line = line.strip()
        if line.startswith('#') or len(line) == 0:
            continue
        v = line.split()
        sl, s = int(v[0]), v[1].lower()
        exp   = True if s == "true"  or s == "t" else False
        

        z = (sl, exp)
        tests.append(z)

    #print tests

    i = 0
    secs = 0
    for sl, exp in tests:
        secs += sl
        simulated_time.elapsed(sl)
        ok = r.limit()
        s = "%4d:  %2d: %5s/%5s [%3d]\n" % (secs, i, ok, exp, sl)
        sys.stdout.write(s)

        i += 1



if __name__ == '__main__':
    test_rl(sys.stdin)

