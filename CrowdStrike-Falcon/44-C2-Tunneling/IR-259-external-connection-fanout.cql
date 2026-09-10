// IR-259 - External Connection Fan-Out by Host
// Purpose: Identify endpoints contacting many distinct public IPs.
#event_simpleName=NetworkConnectIP4
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| groupBy([ComputerName], function=[count(as=Connections),count(RemoteAddressIP4,distinct=true,as=UniquePublicIPs),collect([ContextBaseFileName,RemotePort])], limit=max)
| sort(UniquePublicIPs, order=desc)