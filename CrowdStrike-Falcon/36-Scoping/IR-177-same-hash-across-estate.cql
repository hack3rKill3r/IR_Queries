// IR-177 - Same SHA256 Across Estate
// Replace SHA256 with the hash under investigation.
#event_simpleName=ProcessRollup2
SHA256HashData="SHA256"
| groupBy([ComputerName], function=[count(as=Executions),collect([UserName,FileName,FilePath,CommandLine])], limit=max)