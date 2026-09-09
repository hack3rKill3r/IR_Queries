// IR-087 - LOLBin Network Activity
#event_simpleName=NetworkConnectIP4 ContextBaseFileName=/^(certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)