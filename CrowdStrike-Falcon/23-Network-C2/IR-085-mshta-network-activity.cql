// IR-085 - MSHTA Network Activity
#event_simpleName=NetworkConnectIP4 ContextBaseFileName="mshta.exe"
| table([@timestamp,ComputerName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)