#/bin/bash

PORT="$1"
ADDR="127.0.0.1"

echo "PORT=$PORT"
echo "ADDR=$ADDR"

sleep 3600

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
