// IR-380 - Discovery / Collection / Staging Super Query
#event_simpleName=ProcessRollup2
(FileName=/^(whoami|hostname|systeminfo|ipconfig|arp|route|netstat|quser|qwinsta|nltest|net|net1|dsquery|nslookup|robocopy|xcopy|7z|7za|7zz|rar|winrar|tar)\.exe$/i OR CommandLine=/(Get-ADUser|Get-DomainUser|SharpHound|adfind|Get-ChildItem|Get-Clipboard|screenshot|Login Data|key4\.db|\.pst|Compress-Archive|password|credential|secret|confidential|finance|payroll)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)