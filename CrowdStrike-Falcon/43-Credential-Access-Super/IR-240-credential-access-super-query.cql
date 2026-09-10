// IR-240 - Credential Access Super Query
// Purpose: Broad first-pass hunt for credential dumping, hive access, DPAPI abuse, browser credential access, and Kerberos ticket tooling.
#event_simpleName=ProcessRollup2
(
  FileName=/^(procdump|procdump64|rundll32|reg|ntdsutil|klist|createdump|dotnet-dump)\.exe$/i
  OR CommandLine=/(lsass|comsvcs\.dll.*MiniDump|ntds\.dit|secretsdump|lsadump|dcsync|DPAPI|CryptUnprotectData|Login Data|key4\.db|logins\.json|Rubeus.*(dump|triage|ptt|kerberoast|asreproast|golden|silver)|krbtgt)/i
)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId], limit=20000)