// IR-152 - BloodHound Collection Output Artifacts
// Purpose: Identify common BloodHound/SharpHound JSON collection output.
#event_simpleName=/FileWritten$/
TargetFileName=/(computers|users|groups|domains|gpos|ous|containers|sessions|azure).*\.json$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)