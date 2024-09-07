#!/usr/bin/env nu

# Requirements for running this script:
# - nushell itself
# - pueue
# - GNU time
#
# This Nushell script is also a Nushell module that can be `use`d.

use std log
use std null-device

const $proxy_port = 4000
const $iperf_c_port = 5000
const $iperf_s_port = 5001
const $iperf_duration = 300
const $addr = "127.0.0.1"
const $bench_folder = "jetsocat-bench-out"
const $results_folder = $bench_folder | path join "results"
const $bin_folder = $bench_folder | path join "bin"
const $pueue_group = "iperf-bench"

export def main [ ] {
  print $"proxy_port='($proxy_port)'"
  print $"iperf_c_port='($iperf_c_port)'"
  print $"iperf_s_port='($iperf_s_port)'"
  print $"iperf_duration='($iperf_duration)'"
  print $"addr='($addr)'"
  print $"bench_folder='($bench_folder)'"
  print $"results_folder='($results_folder)'"
  print $"bin_folder='($bin_folder)'"
  print $"pueue_group='($pueue_group)'"
  print "Script subcommands: `run`, `build`, `build-run`"
}

def run_iperf [binary_path: path, par_con_count: int, name: string] {
  let $par_con_count_padded = ($par_con_count | fill -a right -c '0' -w 3)
  let $server_node_log_file = $results_folder | path join $"server-node.($name).($par_con_count_padded).log"
  let $server_node_peak_used_mem_file = $results_folder | path join $"server-node.($name).($par_con_count_padded).peak-used-mem"
  let $client_node_log_file = $results_folder | path join $"client-node.($name).($par_con_count_padded).log"
  let $client_node_peak_used_mem_file = $results_folder | path join $"client-node.($name).($par_con_count_padded).peak-used-mem"
  let $iperf_csv_file = $results_folder | path join $"iperf.($name).($par_con_count_padded).csv"

  log debug $"server_node_log_file='($server_node_log_file)'"
  log debug $"server_node_peak_used_mem_file='($server_node_peak_used_mem_file)'"
  log debug $"client_node_log_file='($client_node_log_file)'"
  log debug $"client_node_peak_used_mem_file='($client_node_peak_used_mem_file)'"
  log debug $"iperf_csv_file='($iperf_csv_file)'"

  log debug "Start server node"
  let $server_node_id = pueue add -g $pueue_group -p -- time -f "%MKB" -- $binary_path jmux-proxy $"tcp-listen://127.0.0.1:($proxy_port)" --allow-all --log-file $server_node_log_file
  sleep 1sec

  log debug "Start client node"
  let $client_node_id = pueue add -g $pueue_group -p -- time -f "%MKB" -- $binary_path jmux-proxy $"tcp://127.0.0.1:($proxy_port)" $"tcp-listen://127.0.0.1:($iperf_c_port)/127.0.0.1:($iperf_s_port)" --log-file $client_node_log_file
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

def benchmark [binary_path: path] {
  let $name = $binary_path | path parse | get stem

  log info ('' | fill --width 40 --character '=')
  log info ($" ($name) " | fill --alignment center --width 40 --character '=')
  log info ('' | fill --width 40 --character '=')

  log debug $"binary_path='($binary_path)'"

  def batch_run_helper [name: string] {
    [1 2 10] | each { |$n|
      log info $"==> ($n) connection\(s)"
      run_iperf $binary_path $n $name
    }
  }

  try {
    sudo tc qdisc add dev lo root handle 1:0 netem delay 50msec o+e> (null-device)
    log info "==> Enabled delay of 50msec"
  } catch {
    log info "==> Delay already enabled"
  }
  let $delay_results = batch_run_helper $"($name).delay"

  sudo tc qdisc del dev lo root
  log info "==> Disabled delay"
  let $nodelay_results = batch_run_helper $"($name).nodelay"

  [...$delay_results ...$nodelay_results]
}

def pueue_cleanup [] {
  log debug "Clean up procedure"

  try {
    pueue kill -g $pueue_group o+e> (null-device)
    pueue clean -g $pueue_group o+e> (null-device)
    pueue group remove $pueue_group o+e> (null-device)
  }
}

def make_folders [] {
  mkdir $results_folder
  mkdir $bin_folder
}

# Benchmark binaries found in the bench folder
def "main run" [ ] {
  log info "Run benchmarks..."

  make_folders

  try {
    log info "Start pueue deamon"
    pueued e> (null-device)
  } catch {
    log warning "Failed to start the pueue deamon; it is likely already started"
  }

  pueue_cleanup

  pueue group add $pueue_group o+e> (null-device)
  pueue parallel -g $pueue_group 2 o+e> (null-device)

  let $results = ls $bin_folder | get name | each { |$binary_path| benchmark $binary_path } | flatten

  pueue_cleanup

  $results
}

# Benchmark binaries found in the bench folder
export def "run" [ ] {
  main run
}

# Build binaries to benchmark from Git branches and move them to the bench folder
def "main build" [
  target_path: path # Path to cargo’s target folder
  ...branches: string # Git branches to benchmark
] {
  log info "Build binaries..."

  make_folders

  for $branch in $branches {
    log info $"Build jetsocat binary on branch '($branch)'..."
    git checkout $branch
    cargo build -p jetsocat --release
    let $bin_name = ($branch | str replace '/' '-')
    cp $"($target_path)/release/jetsocat" $"($bin_folder)/($bin_name)"
  }
}

# Build binaries to benchmark from Git branches and move them to the bench folder
export def "build" [
  target_path: path # Path to cargo’s target folder
  ...branches: string # Git branches to benchmark
] {
  main build $target_path ...$branches
}

# Build binaries and run the benchmarks
def "main build-run" [
  target_path: path # Path to cargo’s target folder
  ...branches: string # Git branches to benchmark
] {
  main build $target_path ...$branches o+e> (null-device)
  main run
}

# Build binaries and run the benchmarks
export def "build-run" [
  target_path: path # Path to cargo’s target folder
  ...branches: string # Git branches to benchmark
] {
  main build-run $target_path ...$branches
}

# Generate a markdown table summarizing the results
#
# The input is expected to have the following type:
#   table<name: string, parallel_connections: int, average_throughput_per_sec: filesize, server_node_peak_used_mem: filesize, client_node_peak_used_mem: filesize>
export def "mdtable" [ ] {
  let $results = $in
  print "| Name | Parallel connections | Average throughput | Server node peak memory usage | Client node peak memory usage |"
  print "|------|----------------------|--------------------|-------------------------------|-------------------------------|"
  for $result in $results {
    print $"|($result.name)|($result.parallel_connections)|($result.average_throughput_per_sec)/s|($result.server_node_peak_used_mem)|($result.client_node_peak_used_mem)|";
  }
}
