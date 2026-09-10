// IR-264 - Archive Then Transfer
// Purpose: Correlate archive-tool execution followed by transfer-tool execution on the same endpoint/user.
// MITRE ATT&CK: T1560.001 / T1048
correlate(
  archive: {
    #event_simpleName=ProcessRollup2
    FileName=/^(7z|7za|7zz|rar|winrar|tar)\.exe$/i
  } include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
  transfer: {
    #event_simpleName=ProcessRollup2
    FileName=/^(rclone|winscp|winscp\.com|curl|ftp|filezilla)\.exe$/i
    | aid <=> archive.aid
    | UserName <=> archive.UserName
  } include:[aid,ComputerName,UserName,FileName,CommandLine],
  sequence=true,
  within=60m
)