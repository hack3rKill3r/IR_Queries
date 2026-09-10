// IR-326 - PowerShell Logging Bypass Indicators
// Purpose: Identify command lines attempting to weaken script block/module/transcription logging.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(ScriptBlockLogging|ModuleLogging|Transcription|EnableScriptBlockLogging|EnableModuleLogging)/i
CommandLine=/(0|false|disable|delete|remove)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)