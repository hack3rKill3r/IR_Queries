// IR-500 - Credential Access / Identity Attack Super Query
// Purpose: Broad first-pass hunt for credential dumping, hive/NTDS access, Kerberos abuse, DPAPI, browser credential theft, and token abuse.
#event_simpleName=ProcessRollup2
(
 FileName=/^(procdump|procdump64|rundll32|reg|ntdsutil|klist)\.exe$/i
 OR
 CommandLine=/(lsass|comsvcs\.dll.*MiniDump|ntds\.dit|secretsdump|mimikatz|lsadump|dcsync|kerberoast|asreproast|Rubeus.*(dump|triage|ptt|golden|silver)|krbtgt|DPAPI|CryptUnprotectData|Login Data|key4\.db|logins\.json|lazagne|steal_token|make_token)/i
)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId],limit=20000)