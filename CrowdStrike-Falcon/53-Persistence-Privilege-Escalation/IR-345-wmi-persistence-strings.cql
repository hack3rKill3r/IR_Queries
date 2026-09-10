// IR-345 - WMI Event Subscription Persistence Strings
// Purpose: Hunt for common permanent WMI subscription classes.
// MITRE ATT&CK: T1546.003
#event_simpleName=ProcessRollup2
CommandLine=/(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|root\\subscription)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)