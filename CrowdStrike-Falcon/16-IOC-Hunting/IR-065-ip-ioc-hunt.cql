// IR-065 - IPv4 IOC Hunt
// Replace IOC_IP with the IPv4 indicator.
#event_simpleName=NetworkConnectIP4
(RemoteAddressIP4="IOC_IP" OR LocalAddressIP4="IOC_IP")
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)