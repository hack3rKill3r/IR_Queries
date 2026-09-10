// IR-263 - WinSCP Network Activity
// Purpose: Identify WinSCP outbound connections.
// MITRE ATT&CK: T1048 / T1567
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/^(winscp|winscp\.com)\.exe$/i
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)