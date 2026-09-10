// IR-106 - DNS Requests from Windows Script Hosts
// Purpose: Identify DNS activity associated with wscript.exe or cscript.exe.
#event_simpleName=DnsRequest
ContextBaseFileName=/^(wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)