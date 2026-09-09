// IR-076 - Specific Remote IPv4 Address
// Replace IOC_IP with the destination/source under investigation.
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="IOC_IP"
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)