// IR-254 - Suspicious Process External Network Activity
// Purpose: Identify outbound public connections from high-interest interpreters/LOLBins.
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/^(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript|wmic|certutil|bitsadmin)\.exe$/i
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)