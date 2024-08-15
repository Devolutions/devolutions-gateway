# JMUX proxy performance

This document explains how we evaluated and improved the performance of our JMUX proxy implementation.

## Measurement procedure

Throughput and performance is measured locally on a Linux machine.
[`iperf`](https://en.wikipedia.org/wiki/Iperf) is used for measuring the network performance.
Wide area network delays is emulated using [`netem`](https://wiki.linuxfoundation.org/networking/netem).

6 measures are performed:

- 1 connection with emulated delay of 50msec
- 2 connections with emulated delay of 50msec
- 10 connections with emulated delay of 50msec
- 1 connection without delay
- 2 connections without delay
- 10 connections without delay

Jetsocat is built using the `profiling` profile, and two instances are run:

```shell
jetsocat jmux-proxy tcp-listen://127.0.0.1:5009 --allow-all
```

```shell
jetsocat jmux-proxy tcp://127.0.0.1:5009 tcp-listen://127.0.0.1:5000/127.0.0.1:5001
```

`iperf` is then run 6 times using the following script:

```bash
#/bin/bash

PORT="$1"
ADDR="127.0.0.1"

echo "PORT=$PORT"
echo "ADDR=$ADDR"

tc qdisc add dev lo root handle 1:0 netem delay 50msec
echo "==> Enabled delay of 50msec"

echo "==> 1 connection"
iperf -c "$ADDR" -p "$PORT" -P 1 -t 600

sleep 5
echo "==> 2 connections"
iperf -c "$ADDR" -p "$PORT" -P 2 -t 600

sleep 5
echo "==> 10 connections"
iperf -c "$ADDR" -p "$PORT" -P 10 -t 600

sleep 5
tc qdisc del dev lo root
echo "==> Disabled delay"

echo "==> 1 connection"
iperf -c "$ADDR" -p $PORT -P 1 -t 600

sleep 5
echo "==> 2 connections"
iperf -c "$ADDR" -p $PORT -P 2 -t 600

sleep 5
echo "==> 10 connections"
iperf -c "$ADDR" -p $PORT -P 10 -t 600
```

Let’s assume the script is in a file named `run_iperf.sh`.

It's important to note that `iperf` should be run for an extended period to account for the initial filling of TCP socket buffers,
which can artificially inflate the average throughput if tested for less than a minute.
Running `iperf` for 10 minutes is enough to ensure the results accurately reflect the effective average throughput.

## Applied optimizations

- <https://github.com/Devolutions/devolutions-gateway/pull/973>
- <https://github.com/Devolutions/devolutions-gateway/pull/975>
- <https://github.com/Devolutions/devolutions-gateway/pull/976>
- <https://github.com/Devolutions/devolutions-gateway/pull/977>
- <https://github.com/Devolutions/devolutions-gateway/pull/980>

## Measures

Results obtained following the above procedure.

### Direct (no JMUX proxy)

`iperf` client is run against the server directly, without using the JMUX proxy in-between.

```shell
./run_iperf.sh 5001
```

The most interesting metric is the 1-connection one, which is the best we can hope to achieve.
The JMUX proxy is multiplexing many connections into a single one.
In other words, the maximum overall throughput we can hope to achieve using the JMUX proxy is the same as the direct 1-connection one.

#### With 50ms delay on loopback

1 connection:

```
[  1] 0.0000-600.2051 sec  16.1 GBytes   230 Mbits/sec
```

#### Without delay

1 connection:

```
[  1] 0.0000-600.0059 sec  6.84 TBytes   100 Gbits/sec
```

### Old unoptimized JMUX proxy up to 2024.3.1

This time, `iperf` client is run against the JMUX proxy and redirected to the server.

```shell
./run_iperf.sh 5000
```

#### With 50ms delay on loopback

1 connection:

```
[  1] 0.0000-637.5385 sec  66.2 MBytes   871 Kbits/sec
```

2 connections:

```
[  2] 0.0000-637.1529 sec  66.4 MBytes   874 Kbits/sec
[  1] 0.0000-637.4966 sec  66.4 MBytes   874 Kbits/sec
[SUM] 0.0000-637.4967 sec   133 MBytes  1.75 Mbits/sec
```

10 connections:

```
[  6] 0.0000-627.8686 sec  85.9 MBytes  1.15 Mbits/sec
[  4] 0.0000-627.8686 sec  86.5 MBytes  1.16 Mbits/sec
[  2] 0.0000-627.9682 sec  86.3 MBytes  1.15 Mbits/sec
[  8] 0.0000-628.0679 sec  86.5 MBytes  1.15 Mbits/sec
[  1] 0.0000-628.0678 sec  86.5 MBytes  1.16 Mbits/sec
[ 10] 0.0000-628.0682 sec  86.6 MBytes  1.16 Mbits/sec
[  7] 0.0000-628.1684 sec  86.2 MBytes  1.15 Mbits/sec
[  9] 0.0000-628.1675 sec  87.0 MBytes  1.16 Mbits/sec
[  5] 0.0000-628.2687 sec  86.6 MBytes  1.16 Mbits/sec
[  3] 0.0000-628.3688 sec  86.4 MBytes  1.15 Mbits/sec
[SUM] 0.0000-628.3700 sec   865 MBytes  11.5 Mbits/sec
```

The more we have connections, the more the overall throughput is high.
This shows that our control flow algorithm is not efficient.

#### Without delay

1 connection:

```
[  1] 0.0000-600.0517 sec   468 GBytes  6.70 Gbits/sec
```

2 connections:

```
[  2] 0.0000-600.0294 sec   152 GBytes  2.18 Gbits/sec
[  1] 0.0000-600.0747 sec   152 GBytes  2.18 Gbits/sec
[SUM] 0.0000-600.0747 sec   305 GBytes  4.36 Gbits/sec
```

10 connections:

```
[  6] 0.0000-600.1632 sec  32.7 GBytes   467 Mbits/sec
[ 10] 0.0000-600.1636 sec  32.7 GBytes   467 Mbits/sec
[  3] 0.0000-600.1635 sec  32.7 GBytes   467 Mbits/sec
[  7] 0.0000-600.1633 sec  32.7 GBytes   467 Mbits/sec
[  4] 0.0000-600.1633 sec  32.7 GBytes   467 Mbits/sec
[  5] 0.0000-600.1641 sec  32.7 GBytes   467 Mbits/sec
[  8] 0.0000-600.1635 sec  32.7 GBytes   467 Mbits/sec
[  2] 0.0000-600.1634 sec  32.7 GBytes   467 Mbits/sec
[  9] 0.0000-600.1633 sec  32.7 GBytes   467 Mbits/sec
[  1] 0.0000-600.1632 sec  32.7 GBytes   467 Mbits/sec
[SUM] 0.0000-600.1641 sec   327 GBytes  4.67 Gbits/sec
```

### New optimized JMUX proxy starting 2024.3.2

Again, `iperf` client is run against the JMUX proxy and redirected to the server.

```shell
./run_iperf.sh 5000
```

#### With 50ms delay on loopback

1 connection:

```
[  1] 0.0000-600.4197 sec  16.1 GBytes   230 Mbits/sec
```

2 connections:

```
[  1] 0.0000-605.0387 sec  8.19 GBytes   116 Mbits/sec
[  2] 0.0000-605.1395 sec  8.19 GBytes   116 Mbits/sec
[SUM] 0.0000-605.1395 sec  16.4 GBytes   233 Mbits/sec
```

10 connections:

```
[  3] 0.0000-625.7966 sec  1.69 GBytes  23.2 Mbits/sec
[  8] 0.0000-625.9956 sec  1.69 GBytes  23.2 Mbits/sec
[  1] 0.0000-626.0966 sec  1.69 GBytes  23.2 Mbits/sec
[  5] 0.0000-626.0964 sec  1.69 GBytes  23.2 Mbits/sec
[  2] 0.0000-626.1983 sec  1.69 GBytes  23.2 Mbits/sec
[  7] 0.0000-626.1964 sec  1.69 GBytes  23.2 Mbits/sec
[  6] 0.0000-626.1964 sec  1.69 GBytes  23.2 Mbits/sec
[  9] 0.0000-626.1981 sec  1.69 GBytes  23.2 Mbits/sec
[ 10] 0.0000-626.2973 sec  1.69 GBytes  23.2 Mbits/sec
[  4] 0.0000-626.3984 sec  1.69 GBytes  23.2 Mbits/sec
[SUM] 0.0000-626.3986 sec  16.9 GBytes   232 Mbits/sec
```

We are able to reach the same throughput as our "direct" baseline.
This shows that the flow control algorithm is not getting in the way anymore.

#### Without delay

1 connection:

```
[  1] 0.0000-600.0518 sec  1.33 TBytes  19.4 Gbits/sec
```

2 connections:

```
[  2] 0.0000-600.0706 sec   681 GBytes  9.75 Gbits/sec
[  1] 0.0000-600.0705 sec   681 GBytes  9.75 Gbits/sec
[SUM] 0.0000-600.0705 sec  1.33 TBytes  19.5 Gbits/sec
```

10 connections:

```
[  3] 0.0000-600.3608 sec   112 GBytes  1.60 Gbits/sec
[  5] 0.0000-600.3606 sec   112 GBytes  1.60 Gbits/sec
[  6] 0.0000-600.3605 sec   112 GBytes  1.60 Gbits/sec
[  8] 0.0000-600.3598 sec   112 GBytes  1.60 Gbits/sec
[  7] 0.0000-600.3594 sec   112 GBytes  1.60 Gbits/sec
[  1] 0.0000-600.3606 sec   112 GBytes  1.60 Gbits/sec
[  9] 0.0000-600.3597 sec   112 GBytes  1.60 Gbits/sec
[ 10] 0.0000-600.3606 sec   112 GBytes  1.60 Gbits/sec
[  2] 0.0000-600.3602 sec   112 GBytes  1.60 Gbits/sec
[  4] 0.0000-600.3719 sec   112 GBytes  1.60 Gbits/sec
[SUM] 0.0000-600.3721 sec  1.09 TBytes  16.0 Gbits/sec
```

Even without delay, the throughput is greatly improved over the unoptimized version.
Improved CPU usage is allowing more bytes to be processed in the same amount of time.

## Analysis

The flow control algorithm, particularly the window size, is a critical parameter for maintaining good throughput, especially when wide area network delays are present.
Since such delays are common in almost all practical setups, it’s safe to say that this is the most important metric to optimize.

Other optimizations, while beneficial, primarily serve to reduce CPU usage and increase throughput on very high-speed networks.
A speed of 30 Mbits/s is already considered high, but networks with throughput exceeding 1 Gbits/s also exist (e.g.: ultra-high speed local area networks).
Enhancing performance for these networks is valuable, particularly in reducing CPU usage as the volume of data processed increases.

Measurements indicate that our JMUX proxy should perform well, even on high-speed networks.
It is capable of matching the throughput of a direct connection, even at speeds of 230 Mbits/s.
At this rate, network overhead remains a more significant factor than the speed at which we can reframe for (de)multiplexing.

Of course, this benchmark has some limitations: for the sake of reproducibility, it assumes a perfect network where no packets are lost.
In real-world wide-area networks, packet loss will inevitably occur.

Nevertheless, these results provide valuable data, confirming that our optimizations are effective with a high degree of confidence.
While further optimization could be pursued to address more specific scenarios, the current implementation is likely sufficient for most practical purposes.

## 2025.2.0 update

Related patches:

- <https://github.com/Devolutions/devolutions-gateway/pull/974>
- <https://github.com/Devolutions/devolutions-gateway/pull/979>

### Results

```shell
./run_iperf.sh 5000
```

#### With 50ms delay on loopback

1 connection:

```
[  1] 0.0000-600.4552 sec  16.1 GBytes   231 Mbits/sec
```

2 connections:

```
[  1] 0.0000-605.1600 sec  8.16 GBytes   116 Mbits/sec
[  2] 0.0000-605.1599 sec  8.16 GBytes   116 Mbits/sec
[SUM] 0.0000-605.1599 sec  16.3 GBytes   232 Mbits/sec
```

10 connections:

```
[  8] 0.0000-625.8346 sec  1.69 GBytes  23.2 Mbits/sec
[  9] 0.0000-626.1828 sec  1.69 GBytes  23.2 Mbits/sec
[  2] 0.0000-626.1820 sec  1.69 GBytes  23.2 Mbits/sec
[  5] 0.0000-626.1817 sec  1.69 GBytes  23.2 Mbits/sec
[  6] 0.0000-626.1815 sec  1.69 GBytes  23.2 Mbits/sec
[  4] 0.0000-626.1827 sec  1.69 GBytes  23.2 Mbits/sec
[  3] 0.0000-626.1814 sec  1.69 GBytes  23.2 Mbits/sec
[  7] 0.0000-626.1821 sec  1.69 GBytes  23.2 Mbits/sec
[  1] 0.0000-626.2831 sec  1.69 GBytes  23.1 Mbits/sec
[ 10] 0.0000-626.2819 sec  1.69 GBytes  23.1 Mbits/sec
[SUM] 0.0000-626.2832 sec  16.9 GBytes   232 Mbits/sec
```

#### Without delay

1 connection:

```
[  1] 0.0000-600.0402 sec  1.68 TBytes  24.6 Gbits/sec
```

2 connections:

```
[  1] 0.0000-600.0628 sec   752 GBytes  10.8 Gbits/sec
[  2] 0.0000-601.0794 sec   751 GBytes  10.7 Gbits/sec
[SUM] 0.0000-601.0794 sec  1.47 TBytes  21.5 Gbits/sec
```

10 connections:

```
[  6] 0.0000-600.3015 sec   127 GBytes  1.82 Gbits/sec
[  3] 0.0000-600.3014 sec   127 GBytes  1.82 Gbits/sec
[  7] 0.0000-600.3012 sec   127 GBytes  1.82 Gbits/sec
[  5] 0.0000-600.2992 sec   127 GBytes  1.82 Gbits/sec
[  9] 0.0000-600.3014 sec   127 GBytes  1.82 Gbits/sec
[  1] 0.0000-600.3006 sec   127 GBytes  1.82 Gbits/sec
[  2] 0.0000-600.3601 sec   127 GBytes  1.82 Gbits/sec
[ 10] 0.0000-600.3592 sec   127 GBytes  1.82 Gbits/sec
[  8] 0.0000-600.3604 sec   127 GBytes  1.82 Gbits/sec
[  4] 0.0000-600.3586 sec   127 GBytes  1.82 Gbits/sec
[SUM] 0.0000-600.3605 sec  1.24 TBytes  18.2 Gbits/sec
```
