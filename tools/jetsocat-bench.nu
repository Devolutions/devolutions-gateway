#/usr/bin/nu

# Requirements for running this script:
# - nushell itself
# - pueue
# - GNU time

use std log
use std null-device

let $proxy_port = 4000
let $iperf_c_port = 5000
let $iperf_s_port = 5001
let $iperf_duration = 300
let $addr = "127.0.0.1"
let $out_folder = "bench_out"
let $pueue_group = "iperf-bench"

def run_iperf [par_con_count: int, name: string] {
  let $name = ($name | str replace '/' '-')
  let $par_con_count_padded = ($par_con_count | fill -a right -c '0' -w 3)
  let $server_node_log_file = $"($out_folder)/server-node.($name).($par_con_count_padded).log"
  let $server_node_peak_used_mem_file = $"($out_folder)/server-node.($name).($par_con_count_padded).peak-used-mem"
  let $client_node_log_file = $"($out_folder)/client-node.($name).($par_con_count_padded).log"
  let $client_node_peak_used_mem_file = $"($out_folder)/client-node.($name).($par_con_count_padded).peak-used-mem"
  let $iperf_csv_file = $"($out_folder)/iperf.($name).($par_con_count_padded).csv"

  log debug $"server_node_log_file = ($server_node_log_file)"
  log debug $"server_node_peak_used_mem_file = ($server_node_peak_used_mem_file)"
  log debug $"client_node_log_file = ($client_node_log_file)"
  log debug $"client_node_peak_used_mem_file = ($client_node_peak_used_mem_file)"
  log debug $"iperf_csv_file = ($iperf_csv_file)"

  log debug "Start server node"
  let $server_node_id = pueue add -g $pueue_group -p -- time -f "%MKB" -- ./target/release/jetsocat jmux-proxy $"tcp-listen://127.0.0.1:($proxy_port)" --allow-all --log-file $server_node_log_file
  sleep 1sec

  log debug "Start client node"
  let $client_node_id = (pueue add -g $pueue_group -p -- time -f "%MKB" -- ./target/release/jetsocat jmux-proxy $"tcp://127.0.0.1:($proxy_port)" $"tcp-listen://127.0.0.1:($iperf_c_port)/127.0.0.1:($iperf_s_port)" --log-file $client_node_log_file)
  sleep 1sec

  log debug "Start iperf"
  iperf -c $addr -p $iperf_c_port -P $par_con_count -t $iperf_duration --sum-only -y c o> $iperf_csv_file

  # Just waiting a little bit more to let things cool down.
  sleep 2sec

  pueue kill -s SIGINT $server_node_id o+e> (null-device)

  pueue wait $server_node_id o+e> (null-device)
  pueue wait $client_node_id o+e> (null-device)

  pueue follow $server_node_id | lines | last o> $server_node_peak_used_mem_file
  pueue follow $client_node_id | lines | last o> $client_node_peak_used_mem_file

  {
    name: $"($name).($par_con_count_padded)",
    parallel_connections: $par_con_count,
    average_throughput_per_sec: (open $iperf_csv_file --raw | split column ',' | get column9 | first | into int | each { |bits_per_sec| $bits_per_sec / 8 } | into filesize),
    server_node_peak_used_mem: (open $server_node_peak_used_mem_file | into filesize),
    client_node_peak_used_mem: (open $client_node_peak_used_mem_file | into filesize),
  }
}

def benchmark [branch: string] {
  log info "============="
  log info $"=== ($branch) ==="
  log info "============="

  git checkout $branch o+e> (null-device)
  cargo build -p jetsocat --release o+e> (null-device)

  try {
    sudo tc qdisc add dev lo root handle 1:0 netem delay 50msec o+e> (null-device)
    log info "==> Enabled delay of 50msec"
  } catch {
    log info "==> Delay already enabled"
  }

  log info "==> 1 connection"
  print (run_iperf 1 $"($branch).delay")

  log info "==> 2 connections"
  print (run_iperf 2 $"($branch).delay")

  log info "==> 10 connections"
  print (run_iperf 10 $"($branch).delay")

  sudo tc qdisc del dev lo root
  log info "==> Disabled delay"

  log info "==> 1 connection"
  print (run_iperf 1 $"($branch).nodelay")

  log info "==> 2 connections"
  print (run_iperf 2 $"($branch).nodelay")

  log info "==> 10 connections"
  print (run_iperf 10 $"($branch).nodelay")
}

def pueue_cleanup [] {
  log debug "Clean up procedure"

  try {
    pueue kill -g $pueue_group o+e> (null-device)
    pueue clean -g $pueue_group o+e> (null-device)
    pueue group remove $pueue_group o+e> (null-device)
  }
}

try {
  log info "Start pueue deamon"
  pueued e> (null-device)
} catch {
  log warning "Failed to start the pueue deamon; it is likely already started"
}

pueue_cleanup

log debug $"PROXY_PORT=($proxy_port)"
log debug $"IPERF_C_PORT=($iperf_c_port)"
log debug $"IPERF_S_PORT=($iperf_s_port)"
log debug $"ADDR=($addr)"
log debug $"IPERF_DURATION=($iperf_duration)"
log debug $"OUT_FOLDER=($out_folder)"
log debug $"PUEUE_GROUP=($pueue_group)"

mkdir $out_folder

pueue group add $pueue_group o+e> (null-device)
pueue parallel -g $pueue_group 2 o+e> (null-device)

benchmark "master"
benchmark "perf/jmux-proxy-7"
benchmark "perf/jmux-proxy-8"
benchmark "perf/jmux-proxy-9"
benchmark "perf/jmux-proxy-10"

pueue_cleanup
