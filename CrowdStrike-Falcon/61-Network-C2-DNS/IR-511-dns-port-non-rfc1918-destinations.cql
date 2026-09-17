// IR-511 - Port 53 Connections to Non-RFC1918 Destinations
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Review direct DNS-port traffic outside common private/local address ranges.
// Requires: NetworkConnectIP4: RemoteAddressIP4, RemotePort, Protocol.
// Analyst notes: A port-only candidate, not decoded DNS. This exclusion list is NOT a complete global-routability or externality test. Add approved resolvers, corporate public ranges and VPN exceptions.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-cidr.html

#event_simpleName=NetworkConnectIP4
RemotePort=53 RemoteAddressIP4=* (Protocol=6 OR Protocol=17)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4"])
| sort(@timestamp, order=asc, limit=20000)
| table([@timestamp, aid, ComputerName, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol], limit=20000)
