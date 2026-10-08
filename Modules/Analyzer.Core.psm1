#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:AppRoot = Join-Path $env:LOCALAPPDATA 'IIS-SMTP-Badmail-Analyzer'
$script:LogRoot = Join-Path $script:AppRoot 'Logs'
$script:ReportRoot = Join-Path $script:AppRoot 'Reports'
$script:ArchiveRoot = Join-Path $script:AppRoot 'Archives'
@($script:AppRoot,$script:LogRoot,$script:ReportRoot,$script:ArchiveRoot) | ForEach-Object { if(-not(Test-Path $_)){New-Item -ItemType Directory -Path $_ -Force | Out-Null} }
$script:LogFile = Join-Path $script:LogRoot ('Analyzer_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')

function Write-AppLog {
 param([string]$Message,[string]$Level='INFO')
 Add-Content -LiteralPath $script:LogFile -Encoding UTF8 -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') + ' [' + $Level + '] ' + $Message)
}
function Test-IsAdministrator {
 $i=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($i)
 $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-PrerequisiteState {
 $pwsh=Get-Command pwsh.exe -ErrorAction SilentlyContinue
 $ad=Get-Module ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue | Select-Object -First 1
 $exo=$false
 if($pwsh){try{$x=& $pwsh.Source -NoProfile -Command "if(Get-Module ExchangeOnlineManagement -ListAvailable){'YES'}else{'NO'}" 2>$null;$exo=($x -contains 'YES')}catch{}}
 @(
 [pscustomobject]@{Requirement='Administrator';Status=$(if(Test-IsAdministrator){'PASS'}else{'INFO'});Detail=$(if(Test-IsAdministrator){'Elevated'}else{'Not elevated'})},
 [pscustomobject]@{Requirement='ActiveDirectory module';Status=$(if($ad){'PASS'}else{'INFO'});Detail=$(if($ad){$ad.Version}else{'Optional; RSAT not installed'})},
 [pscustomobject]@{Requirement='PowerShell 7';Status=$(if($pwsh){'PASS'}else{'INFO'});Detail=$(if($pwsh){$pwsh.Source}else{'Optional; required for EXO'})},
 [pscustomobject]@{Requirement='ExchangeOnlineManagement';Status=$(if($exo){'PASS'}else{'INFO'});Detail=$(if($exo){'Available to PS7'}else{'Optional; not available to PS7'})}
 )
}
function Install-Prerequisite {
 param([string]$Requirement)
 switch($Requirement){
 'ActiveDirectory module' {if(-not(Test-IsAdministrator)){throw 'Elevation is required.'};$c=Get-WindowsCapability -Online|Where-Object Name -like 'Rsat.ActiveDirectory.DS-LDS.Tools*'|Select-Object -First 1;if($c.State -ne 'Installed'){Add-WindowsCapability -Online -Name $c.Name|Out-Null}}
 'PowerShell 7' {$w=Get-Command winget.exe -ErrorAction SilentlyContinue;if(-not $w){throw 'winget is unavailable.'};& $w.Source install --id Microsoft.PowerShell --source winget --accept-package-agreements --accept-source-agreements}
 'ExchangeOnlineManagement' {$p=Get-Command pwsh.exe -ErrorAction SilentlyContinue;if(-not $p){throw 'Install PowerShell 7 first.'};& $p.Source -NoProfile -Command "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber"}
 default {throw 'No installer is defined for this item.'}
 }}
function Find-IisSmtpBadmail {
 param([string]$Server)
 $local=$Server -in @('.','localhost',$env:COMPUTERNAME)
 foreach($drive in 'C','D','E'){
  $root=if($local){$drive+':\inetpub\mailroot'}else{'\\'+$Server+'\'+$drive+'$\inetpub\mailroot'}
  $bad=Join-Path $root 'Badmail'
  if(Test-Path -LiteralPath $bad -ErrorAction SilentlyContinue){[pscustomobject]@{Mailroot=$root;Badmail=$bad}}
 }}
function Test-EmailShape {param([string]$Address);if(-not $Address){return $false};$Address.Trim('<','>',' ') -match '^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$'}
function Get-Classification {param($Status,$Diagnostic,$Bdp,$Recipient);$a="$Status $Diagnostic $Bdp";if($Recipient -and -not(Test-EmailShape $Recipient)){'Malformed Recipient'}elseif($a -match '5\.7\.64|TenantAttribution|UntrustedRootNdr|certificate chain'){'TLS / Tenant Attribution'}elseif($a -match '5\.2\.3|Msg Size|message size|too large'){'Message Too Large'}elseif($a -match '5\.4\.1|Recipient address rejected|user unknown|recipient.*not found'){'Recipient Rejected'}elseif($a -match '\b4\d\d\b'){'Temporary SMTP Failure'}elseif($a -match '\b5\d\d\b'){'Permanent SMTP Failure'}else{'Other'}}
function Get-Remediation {param($r);switch($r.Category){
 'Malformed Recipient' {'Verify and correct the recipient on the originating application or device, then test delivery.'}
 'Recipient Rejected' {if($r.EXOStatus -eq 'Not Found' -and $r.ADStatus -eq 'Not Found'){'Recipient is absent from AD and Exchange Online. Replace or remove it at the source, then retest.'}else{'Validate the recipient in the authoritative mail directory. If obsolete, replace or remove it at the source.'}}
 'Message Too Large' {'Do not change the recipient based on this error. Reduce message or attachment size, or review message-size limits.'}
 'TLS / Tenant Attribution' {'Review the Exchange Online connector and SMTP relay TLS certificate identity, trust chain, expiration, and tenant attribution.'}
 'Temporary SMTP Failure' {'Review retry history, remote availability, DNS, routing, throttling, and queue behavior.'}
 default {'Review the correlated BAD, BDR, and BDP evidence and correct the configuration identified by the SMTP diagnostic.'}
 }}
Export-ModuleMember -Function *