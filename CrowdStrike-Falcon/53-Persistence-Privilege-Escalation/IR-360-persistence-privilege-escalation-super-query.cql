// IR-360 - Persistence / Privilege Escalation Super Query
// Purpose: Broad hunt across scheduled tasks, services, autoruns, WMI subscriptions, UAC bypass, token abuse, and group manipulation.
#event_simpleName=ProcessRollup2
(
 CommandLine=/(Register-ScheduledTask|New-ScheduledTask|New-Service|__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|CurrentVersion\\(Run|RunOnce)|Winlogon.*(Shell|Userinit)|Image File Execution Options|DelegateExecute|AlwaysInstallElevated|token::elevate|steal_token|make_token)/i
 OR
 (FileName=/^(schtasks|sc|reg|fodhelper|computerdefaults|eventvwr|net|net1)\.exe$/i
  CommandLine=/(create|config|\/create|\/add|administrators|domain admins|ms-settings|mscfile)/i)
)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)