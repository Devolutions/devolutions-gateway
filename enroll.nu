#!/usr/bin/env nu
# Demo helper: enroll the local agent with a JWT issued by DVLS.
#
# Usage:
#   nu enroll.nu "<JWT>"
#
# Wipes the previous enrollment, runs `up` with hard-coded advertise lists
# matching the project's smoke-test setup, then starts the agent service in
# the foreground so the demo can show the QUIC connection log live.

def main [jwt: string, name: string = "demo-agent"] {
    let agent = "D:\\dgw-pr2\\target\\release\\devolutions-agent.exe"
    let agent_dir = "C:\\ProgramData\\Devolutions\\Agent"
    let cert_dir = $"($agent_dir)\\certs"
    let agent_json = $"($agent_dir)\\agent.json"

    print "==> Stopping any running agent"
    try { ps | where name == "devolutions-agent.exe" | each { |p| kill $p.pid } | ignore }

    print "==> Wiping previous enrollment state"
    if ($agent_json | path exists) { rm $agent_json }
    if ($cert_dir | path exists) {
        ls $cert_dir | where name =~ '(-cert\.pem|-key\.pem|gateway-ca\.pem)$' | each { |f| rm $f.name } | ignore
    }

    print "==> Bootstrapping agent (devolutions-agent up)"
    ^$agent up --enrollment-string $jwt --name $name --advertise-routes "10.0.0.0/8,192.168.0.0/16" --advertise-domains "it-help.ninja"

    print "==> Starting agent service (foreground, Ctrl-C to stop)"
    ^$agent run
}
