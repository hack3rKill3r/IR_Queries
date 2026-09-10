// IR-260 - C2 / Tunneling Super Query
// Purpose: Broad hunt for remote-access, tunneling, proxying, and suspicious outbound communication tooling.
(
  #event_simpleName=ProcessRollup2
  (
    FileName=/(ngrok|cloudflared|plink|chisel|rclone|anydesk|teamviewer|rustdesk|screenconnect|atera|splashtop)\.exe$/i
    OR CommandLine=/(socks4|socks5|proxychains|ligolo|gost|cloudflared.*tunnel|\s-L\s|\s-R\s|\s-D\s|cobaltstrike|beacon\.dll|sliver)/i
  )
)
OR
(
  #event_simpleName=NetworkConnectIP4
  ContextBaseFileName=/^(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript|ngrok|cloudflared|plink|chisel)\.exe$/i
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ContextBaseFileName,ParentBaseFileName,FileName,FilePath,CommandLine,RemoteAddressIP4,RemotePort,SHA256HashData], limit=20000)