// IR-317 - Docker Host Filesystem Mount
// Purpose: Identify containers mounting sensitive host paths.
#event_simpleName=ProcessRollup2
FileName=/^docker$/i
CommandLine=/(-v|--volume|--mount).*(\/:|\/etc:|\/root:|\/var\/run:)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)