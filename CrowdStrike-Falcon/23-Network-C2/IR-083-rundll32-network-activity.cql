// IR-083 - Rundll32 Network Activity
#event_simpleName=NetworkConnectIP4 ContextBaseFileName="rundll32.exe"
| table([@timestamp,ComputerName,ContextProcessId,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort], limit=20000)