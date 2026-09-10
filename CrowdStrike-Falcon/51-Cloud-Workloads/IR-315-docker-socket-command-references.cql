// IR-315 - Docker Socket References
// Purpose: Identify commands interacting with the Docker daemon socket.
#event_simpleName=ProcessRollup2
CommandLine=/(\/var\/run\/docker\.sock|DOCKER_HOST)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)