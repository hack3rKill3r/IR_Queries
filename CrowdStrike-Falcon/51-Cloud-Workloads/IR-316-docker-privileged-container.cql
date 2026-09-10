// IR-316 - Privileged Docker Container
// Purpose: Identify privileged/container escape-relevant Docker run options.
#event_simpleName=ProcessRollup2
FileName=/^docker$/i
CommandLine=/\brun\b.*(--privileged|--pid[ =]host|--net[ =]host|--network[ =]host|--cap-add[ =]SYS_ADMIN)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)