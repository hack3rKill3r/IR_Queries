// IR-180 - Incident Timeline Super Query
// Replace VICTIM-HOST with the endpoint under investigation.
// Purpose: Build a broad chronological timeline from process, auth, DNS, network, and file-write events.
ComputerName="VICTIM-HOST"
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=NetworkConnectIP4
  OR #event_simpleName=DnsRequest
  OR #event_simpleName=UserLogon
  OR #event_simpleName=UserLogonFailed2
  OR #event_simpleName=/FileWritten$/
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ClientComputerName,ParentBaseFileName,ContextBaseFileName,FileName,FilePath,CommandLine,TargetFileName,DomainName,LocalAddressIP4,RemoteAddressIP4,LocalPort,RemotePort,SHA256HashData,TargetProcessId,ParentProcessId,ContextProcessId,LogonType], limit=20000)
| sort(@timestamp, order=asc)