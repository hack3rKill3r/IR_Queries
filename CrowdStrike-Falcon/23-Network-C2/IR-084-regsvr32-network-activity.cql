// IR-084 - Regsvr32 Network Activity
#event_simpleName=NetworkConnectIP4 ContextBaseFileName="regsvr32.exe"
| table([@timestamp,ComputerName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)