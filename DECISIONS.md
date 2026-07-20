DVLS will intergerate.
all client should be 'transparent' about crendetial injection proxy
so clean it up, goal is to maintain a good maintainbility
commit all in this gateway so far and push, then first let's enable that usecase
extract this to a helper function, semantically sensiable
don't include winrm this time plz, it's out of scope for this PR
well define a trait and directly impl it for credental injection, this handler is wired in many way
go, implement it and let's see
jmux-proxy seam: reframe as a generic per-channel takeover handler (no MITM/RDP concept in the crate); the common (no-handler) path must stay on concrete TcpStream + into_split — only pay the DuplexStream cost when a handler is registered. Keep RdpCredentialInjection::run as the single shared injection entry.
