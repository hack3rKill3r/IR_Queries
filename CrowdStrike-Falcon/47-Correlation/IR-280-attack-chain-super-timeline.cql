// IR-280 - Attack Chain Super Timeline
// Replace VICTIM-HOST with the host under investigation.
// Purpose: Unified chronological view of process, authentication, DNS, network, and file-write telemetry.
ComputerName="VICTIM-HOST"
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=UserLogon
  OR #event_simpleName=UserLogonFailed2
  OR #event_simpleName=DnsRequest
  OR #event_simpleName=NetworkConnectIP4
  OR #event_simpleName=/FileWritten$/
)
| table([@timestamp,#event_simpleName,ComputerName,ClientComputerName,UserName,LogonType,ParentBaseFileName,ContextBaseFileName,FileName,FilePath,CommandLine,TargetFileName,DomainName,LocalAddressIP4,RemoteAddressIP4,LocalPort,RemotePort,SHA256HashData,TargetProcessId,ParentProcessId,ContextProcessId], limit=20000)
| sort(@timestamp, order=asc)