# Entropy Builder

Maintain a certain level of entropy on a system by building hashes off of
system handles and nanoseconds on the clock.

Note: although this is not a pure source of randomness, the chances of
reproducing the exact setup for these hashes is near epsilon, so it may be a
value-add on system on which entropy is consumed quickly.


```
$ ./entropy -h
Entropy builder - maintain a certain level of entropy
Usage of ./entropy:
  -debug
        turn on debug
  -interval duration
        between entropy avail checks (default 1s)
  -min int
        minimum entropy to maintain (default 3000)
```
