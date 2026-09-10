// IR-102 - DNS Requests from PowerShell
// Purpose: Identify DNS activity originating from PowerShell processes.
#event_simpleName=DnsRequest
ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)