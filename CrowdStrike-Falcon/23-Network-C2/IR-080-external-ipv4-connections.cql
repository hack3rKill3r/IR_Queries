// IR-080 - External IPv4 Connections
// Purpose: Remove common private, loopback, and link-local destinations from outbound connection review.
#event_simpleName=NetworkConnectIP4
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"])
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort], limit=20000)