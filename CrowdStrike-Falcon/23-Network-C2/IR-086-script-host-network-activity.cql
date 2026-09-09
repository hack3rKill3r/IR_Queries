// IR-086 - WScript / CScript Network Activity
#event_simpleName=NetworkConnectIP4 ContextBaseFileName=/^(wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)