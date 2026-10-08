#requires -Version 5.1
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

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
function Get-Classification {param($Status,$Diagnostic,$Recipient);$a="$Status $Diagnostic";if($Recipient -and -not(Test-EmailShape $Recipient)){'Malformed Recipient'}elseif($a -match '5\.2\.3|Msg Size|message size|too large'){'Message Too Large'}elseif($a -match '5\.4\.1|Recipient address rejected|user unknown|recipient.*not found'){'Recipient Rejected'}elseif($a -match '5\.7\.64|TenantAttribution|UntrustedRootNdr|certificate chain'){'TLS / Tenant Attribution'}elseif($a -match '\b4\d\d\b'){'Temporary SMTP Failure'}elseif($a -match '\b5\d\d\b'){'Permanent SMTP Failure'}else{'Other'}}
function Get-SecondaryClassification {param([string]$Diagnostic);if(-not $Diagnostic){return $null};if($Diagnostic -match '5\.7\.64|TenantAttribution|UntrustedRootNdr|certificate chain'){'TLS / Tenant Attribution'}elseif($Diagnostic -match '5\.2\.3|Msg Size|message size|too large'){'Message Too Large'}elseif($Diagnostic -match '5\.4\.1|Recipient address rejected'){'Recipient Rejected'}elseif($Diagnostic -match '\b4\d\d\b'){'Temporary SMTP Failure'}elseif($Diagnostic -match '\b5\d\d\b'){'Permanent SMTP Failure'}else{'Other'}}
function Resolve-MessageOrigin {
 param($Headers,$From,$Subject)
 $received=@($Headers|Where-Object {$_})
 $evidence=if($received.Count){[string]$received[-1]}else{$null}
 $host=$null;$ip=$null;$confidence='Low'
 if($evidence){
  if($evidence -match '(?i)\bfrom\s+([^\s\(\[;]+)'){$host=$matches[1].Trim()}
  $ips=@([regex]::Matches($evidence,'(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])') | ForEach-Object {$_.Value})
  if($ips.Count -gt 0){$ip=[string]$ips[0]}
  if($host -or $ip){$confidence='High'}
 }
 $clue=("$host $From $Subject")
 $type='Unknown'
 if($clue -match '(?i)\b(prs[-_ ]?\d+|printer|scanner|scan(?:ned)? image|xerox|sharp|ricoh|canon|laserjet|multifunction|\bmfp\b)'){$type='Printer / MFP'}
 elseif($clue -match '(?i)(solarwinds|network performance monitor|whatsup|wug|monitoring)'){$type='Monitoring / Application'}
 elseif($clue -match '(?i)(ups|eaton|power xpert|storeonce|ilo|infrastructure)'){$type='Infrastructure Device'}
 elseif($host){$type='Server / Application'}
 if(-not $evidence){
  if($From -match '(?i)<([^>]+)>'){$host=($matches[1] -split '@')[0]}
  elseif($From -match '(?i)^([^@\s]+)@'){$host=$matches[1]}
  if($host){$confidence='Low';$evidence='Inferred from message From header only'}
 }
 [pscustomobject]@{OriginHost=$host;OriginIP=$ip;OriginType=$type;OriginConfidence=$confidence;OriginEvidence=$evidence}
}
function Get-Remediation {param($r);$where=if($r.OriginHost -or $r.OriginIP){$originLabel=(@($r.OriginHost,$r.OriginIP)|Where-Object {$_}|Select-Object -Unique -First 2) -join ' / ';' On origin '+$originLabel+':'}else{''};switch($r.Category){
 'Malformed Recipient' {$where+' verify and correct the recipient on the originating application or device, then test delivery.'}
 'Recipient Rejected' {if($r.EXOStatus -eq 'Not Found' -and $r.ADStatus -eq 'Not Found'){$where+' recipient is absent from AD and Exchange Online. Replace or remove it at the source, then retest.'}else{$where+' validate the recipient in the authoritative mail directory. If obsolete, replace or remove it at the source.'}}
 'Message Too Large' {$where+' do not change the recipient based on this error. Reduce message or attachment size, or review message-size limits.'}
 'TLS / Tenant Attribution' {'Review the Exchange Online connector and SMTP relay TLS certificate identity, trust chain, expiration, and tenant attribution.'}
 'Temporary SMTP Failure' {'Review retry history, remote availability, DNS, routing, throttling, and queue behavior.'}
 default {'Review the correlated BAD, BDR, and BDP evidence and correct the configuration identified by the SMTP diagnostic.'}
 }}

function Read-BadMessage {
 param([string]$Path,[int64]$MaxScanBytes=8388608)
 $r=[ordered]@{OriginalFrom=$null;OriginalTo=$null;Subject=$null;FailedRecipient=$null;Status=$null;Diagnostic=$null;TopFrom=$null;TopTo=$null;TopSubject=$null;ReceivedHeaders=@()}
 $fs=[IO.File]::Open($Path,'Open','Read','ReadWrite');$sr=New-Object IO.StreamReader($fs,$true)
 try{
  $bytes=0;$dsn=$false;$inReceived=$false
  while(-not $sr.EndOfStream -and $bytes -lt $MaxScanBytes){
   $line=$sr.ReadLine();$bytes+=$line.Length+2
   if($line -match '^Received:\s*(.*)$'){
    $r.ReceivedHeaders+=($matches[1].Trim());$inReceived=$true
   } elseif($inReceived -and $line -match '^\s+(.+)$'){
    $i=$r.ReceivedHeaders.Count-1;$r.ReceivedHeaders[$i]+=' '+$matches[1].Trim()
   } else {$inReceived=$false}
   if($line -match '^Final-Recipient:\s*(?:rfc822;)?\s*(.+)$'){$r.FailedRecipient=$matches[1].Trim();$dsn=$true}
   elseif($dsn -and $line -match '^Status:\s*(.+)$'){$r.Status=$matches[1].Trim()}
   elseif($dsn -and $line -match '^Diagnostic-Code:\s*(.+)$'){$r.Diagnostic=$matches[1].Trim()}
   elseif($r.Diagnostic -and $dsn -and $line -match '^\s+(.+)$'){$r.Diagnostic+=' '+$matches[1].Trim()}
   if($line -match '^From:\s*(.*)$'){if(-not $r.TopFrom){$r.TopFrom=$matches[1].Trim()}elseif(-not $r.OriginalFrom){$r.OriginalFrom=$matches[1].Trim()}}
   elseif($line -match '^To:\s*(.*)$'){if(-not $r.TopTo){$r.TopTo=$matches[1].Trim()}elseif(-not $r.OriginalTo){$r.OriginalTo=$matches[1].Trim()}}
   elseif($line -match '^Subject:\s*(.*)$'){if(-not $r.TopSubject){$r.TopSubject=$matches[1].Trim()}elseif(-not $r.Subject){$r.Subject=$matches[1].Trim()}}
  }
 }finally{$sr.Dispose()}
 if(-not $r.OriginalFrom){$r.OriginalFrom=$r.TopFrom};if(-not $r.OriginalTo){$r.OriginalTo=$r.TopTo};if(-not $r.Subject){$r.Subject=$r.TopSubject}
 [pscustomobject]$r
}
function Read-BdpPrintable {param([string]$Path);if(-not(Test-Path $Path)){return ''};$fs=[IO.File]::OpenRead($Path);$sb=New-Object Text.StringBuilder;$run=New-Object Text.StringBuilder;try{while(($b=$fs.ReadByte()) -ne -1){if(($b -ge 32 -and $b -le 126) -or $b -in 9,10,13){[void]$run.Append([char]$b)}else{if($run.Length -ge 4){[void]$sb.AppendLine($run.ToString())};[void]$run.Clear()}};$sb.ToString()}finally{$fs.Dispose()}}
function Invoke-BadmailAnalysis {
 param([string]$BadmailPath)
 if(-not(Test-Path $BadmailPath)){throw 'Badmail path not found.'}
 foreach($bad in Get-ChildItem $BadmailPath -Filter '*.BAD' -File){
  $base=[IO.Path]::GetFileNameWithoutExtension($bad.Name);$bdp=Join-Path $BadmailPath ($base+'.BDP');$bdr=Join-Path $BadmailPath ($base+'.BDR')
  $h=Read-BadMessage $bad.FullName;$p=Read-BdpPrintable $bdp;$cat=Get-Classification $h.Status $h.Diagnostic $h.FailedRecipient;try{$origin=Resolve-MessageOrigin $h.ReceivedHeaders $h.OriginalFrom $h.Subject}catch{Write-AppLog ('Origin resolution failed for '+$bad.Name+': '+$_.Exception.Message) 'WARNING';$origin=[pscustomobject]@{OriginHost=$null;OriginIP=$null;OriginType='Unknown';OriginConfidence='Low';OriginEvidence='Origin detection error: '+$_.Exception.Message}}
  $secondary=$null;if($p -match '([245]\d\d\s+[245]\.[0-9.]+[^\r\n]*)'){$secondary=$matches[1].Trim()};$secondaryCategory=Get-SecondaryClassification $secondary
  $o=[pscustomobject]@{Date=$bad.LastWriteTime;OriginHost=$origin.OriginHost;OriginIP=$origin.OriginIP;OriginType=$origin.OriginType;OriginConfidence=$origin.OriginConfidence;OriginEvidence=$origin.OriginEvidence;Source=$h.OriginalFrom;FailedRecipient=$h.FailedRecipient;OriginalTo=$h.OriginalTo;Subject=$h.Subject;Status=$h.Status;Category=$cat;Severity=$(if($cat -in 'Temporary SMTP Failure','Other'){'WARNING'}else{'FAIL'});ADStatus='Not Checked';EXOStatus='Not Checked';MessageSizeMB=[math]::Round($bad.Length/1MB,2);Diagnostic=$h.Diagnostic;SecondaryCategory=$secondaryCategory;SecondaryDiagnostic=$secondary;BaseName=$base;BAD=$bad.FullName;BDR=$(if(Test-Path $bdr){$bdr}else{$null});BDP=$(if(Test-Path $bdp){$bdp}else{$null});Remediation=''}
  $o.Remediation=Get-Remediation $o;$o
 }}

function Invoke-ADRecipientValidation {param([object[]]$Rows,[pscredential]$Credential)
 if(-not(Get-Module ActiveDirectory -ListAvailable)){throw 'ActiveDirectory module is not installed.'};Import-Module ActiveDirectory
 $map=@{};foreach($a in $Rows.FailedRecipient|Where-Object {$_}|Sort-Object -Unique){$x=$a.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29');$p=@{LDAPFilter="(|(mail=$x)(proxyAddresses=smtp:$x))";Properties='mail','proxyAddresses';ErrorAction='SilentlyContinue'};if($Credential){$p.Credential=$Credential};$o=Get-ADObject @p|Select-Object -First 1;$map[$a]=if($o){'Found'}else{'Not Found'}}
 foreach($r in $Rows){if($r.FailedRecipient -and $map.ContainsKey($r.FailedRecipient)){$r.ADStatus=$map[$r.FailedRecipient]};$r.Remediation=Get-Remediation $r}
}
function Invoke-EXORecipientValidation {param([object[]]$Rows)
 $pwsh=Get-Command pwsh.exe -ErrorAction SilentlyContinue;if(-not $pwsh){throw 'PowerShell 7 is not installed.'}
 $addresses=@($Rows.FailedRecipient|Where-Object {$_}|Sort-Object -Unique);if(-not $addresses.Count){return}
 $root=Join-Path $env:TEMP ('IISSMTP_'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $root|Out-Null;$input=Join-Path $root 'in.json';$output=Join-Path $root 'out.json';$helper=Join-Path $root 'exo.ps1';$addresses|ConvertTo-Json|Set-Content $input -Encoding UTF8
 $code=@(
  'param($InputFile,$OutputFile)'
  '$ErrorActionPreference = ''Stop'''
  'Import-Module ExchangeOnlineManagement'
  'Connect-ExchangeOnline -Device -ShowBanner:$false'
  'try {'
  '  $a = @(Get-Content -Raw $InputFile | ConvertFrom-Json)'
  '  $r = foreach($x in $a) {'
  '    $o = Get-EXORecipient -Identity $x -ErrorAction SilentlyContinue'
  '    [pscustomobject]@{ Address=$x; Status=$(if($o){''Found''}else{''Not Found''}) }'
  '  }'
  '  $r | ConvertTo-Json | Set-Content $OutputFile -Encoding UTF8'
  '} finally {'
  '  Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue'
  '}'
 )
 $code|Set-Content $helper -Encoding UTF8
 try{$args='-NoProfile -File "'+$helper+'" -InputFile "'+$input+'" -OutputFile "'+$output+'"';$p=Start-Process $pwsh.Source -ArgumentList $args -Wait -PassThru;if($p.ExitCode -ne 0 -or -not(Test-Path $output)){throw 'Exchange Online validation did not complete. No recipients were marked Not Found.'};$map=@{};foreach($x in @(Get-Content -Raw $output|ConvertFrom-Json)){$map[$x.Address]=$x.Status};foreach($r in $Rows){if($r.FailedRecipient -and $map.ContainsKey($r.FailedRecipient)){$r.EXOStatus=$map[$r.FailedRecipient]};$r.Remediation=Get-Remediation $r}}finally{Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue}
}

$script:ReportRoot=Join-Path (Join-Path $env:LOCALAPPDATA 'IIS-SMTP-Badmail-Analyzer') 'Reports'
$script:ArchiveRoot=Join-Path (Join-Path $env:LOCALAPPDATA 'IIS-SMTP-Badmail-Analyzer') 'Archives'
@($script:ReportRoot,$script:ArchiveRoot)|ForEach-Object{if(-not(Test-Path $_)){New-Item -ItemType Directory -Path $_ -Force|Out-Null}}
function Export-AnalyzerReport {param([object[]]$Rows,[string]$Server,[string]$BadmailPath)
 $stamp=Get-Date -Format 'yyyyMMdd_HHmmss';$safe=$Server -replace '[^A-Za-z0-9._-]','_';$html=Join-Path $script:ReportRoot ('SMTP-Badmail-Report_'+$safe+'_'+$stamp+'.html');$csv=[IO.Path]::ChangeExtension($html,'.csv')
 $e=[Net.WebUtility];$sb=New-Object Text.StringBuilder
 [void]$sb.Append("<!doctype html><meta charset='utf-8'><title>IIS SMTP Badmail Analyzer</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#202124}h1,h2{color:#17365d}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d7de;padding:7px;vertical-align:top}th{background:#f3f6f9}.FAIL{color:#a40000;font-weight:600}.WARNING{color:#8a5a00;font-weight:600}</style><h1>IIS SMTP Badmail Analyzer</h1>")
 [void]$sb.Append('<p><b>SMTP server:</b> '+$e::HtmlEncode($Server)+'<br><b>Badmail:</b> '+$e::HtmlEncode($BadmailPath)+'<br><b>Generated:</b> '+(Get-Date)+'</p>')
 [void]$sb.Append('<h2>Executive Summary</h2><p>Messages: '+$Rows.Count+' | Unique failed recipients: '+@($Rows.FailedRecipient|Where-Object {$_}|Sort-Object -Unique).Count+'</p>')
 [void]$sb.Append('<h2>Findings and Remediation</h2><table><tr><th>Date</th><th>Severity</th><th>Origin</th><th>Origin Type</th><th>Confidence</th><th>Source</th><th>Recipient</th><th>Category</th><th>AD</th><th>EXO</th><th>Evidence</th><th>Remediation</th></tr>')
 foreach($r in $Rows|Sort-Object Date -Descending){$ev=($r.Diagnostic,$r.SecondaryDiagnostic|Where-Object {$_}) -join ' | ';[void]$sb.Append('<tr><td>'+$r.Date+'</td><td class="'+$r.Severity+'">'+$r.Severity+'</td><td>'+$e::HtmlEncode((@($r.OriginHost,$r.OriginIP)|Where-Object {$_}) -join ' / ')+'</td><td>'+$e::HtmlEncode([string]$r.OriginType)+'</td><td>'+$e::HtmlEncode([string]$r.OriginConfidence)+'</td><td>'+$e::HtmlEncode([string]$r.Source)+'</td><td>'+$e::HtmlEncode([string]$r.FailedRecipient)+'</td><td>'+$e::HtmlEncode($r.Category)+'</td><td>'+$r.ADStatus+'</td><td>'+$r.EXOStatus+'</td><td>'+$e::HtmlEncode($ev)+'</td><td>'+$e::HtmlEncode($r.Remediation)+'</td></tr>')}
 [void]$sb.Append('</table><p>Not Checked means directory validation was not performed. It does not mean the recipient is absent.</p>');[IO.File]::WriteAllText($html,$sb.ToString(),[Text.Encoding]::UTF8);$Rows|Export-Csv $csv -NoTypeInformation -Encoding UTF8;[pscustomobject]@{Html=$html;Csv=$csv}
}
function New-BadmailArchive {param([string]$BadmailPath,[string]$Server);Add-Type -AssemblyName System.IO.Compression.FileSystem;$zip=Join-Path $script:ArchiveRoot (($Server -replace '[^A-Za-z0-9._-]','_')+'_Badmail_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.zip');$stage=Join-Path $env:TEMP ('Badmail_'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $stage|Out-Null;try{Get-ChildItem $BadmailPath -File|Where-Object Extension -in '.BAD','.BDR','.BDP'|Copy-Item -Destination $stage;[IO.Compression.ZipFile]::CreateFromDirectory($stage,$zip)}finally{Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue};$zip}

$script:Rows=@();$script:Badmail=$null;$script:Server=$null;$script:Credential=$null
[xml]$x=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="IIS SMTP Badmail Analyzer" Height="780" Width="1250" WindowStartupLocation="CenterScreen">
<Grid Margin="12"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<StackPanel><TextBlock Text="IIS SMTP Badmail Analyzer" FontSize="24" FontWeight="SemiBold"/><TextBlock Text="Discovery, Badmail analysis, recipient validation, and remediation reporting" Foreground="DimGray" Margin="0,2,0,10"/></StackPanel>
<TabControl Grid.Row="1" Name="Tabs">
<TabItem Header="Setup"><Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
<Grid><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
<TextBlock Text="SMTP server" Margin="5"/><TextBox Name="Server" Grid.Column="1" Margin="5"/><Button Name="Discover" Grid.Column="2" Margin="5" Padding="14,5" Content="Discover Mailroot"/>
<TextBlock Grid.Row="1" Text="Badmail path" Margin="5"/><TextBox Name="Path" Grid.Row="1" Grid.Column="1" Margin="5"/><Button Name="Browse" Grid.Row="1" Grid.Column="2" Margin="5" Padding="14,5" Content="Browse"/>
<CheckBox Name="AltCred" Grid.Row="2" Grid.Column="1" Margin="5" Content="Use alternate Windows credentials"/></Grid>
<GroupBox Header="Prerequisites" Grid.Row="1" Margin="0,10"><StackPanel><DataGrid Name="Prereq" Height="190" AutoGenerateColumns="True" IsReadOnly="True"/><StackPanel Orientation="Horizontal"><Button Name="RefreshPre" Content="Refresh" Margin="5" Padding="14,5"/><Button Name="InstallPre" Content="Install Selected" Margin="5" Padding="14,5"/></StackPanel></StackPanel></GroupBox>
<TextBlock Grid.Row="2" TextWrapping="Wrap" Text="Analysis is read-only. Optional requirements are never installed silently. Credentials remain in memory only."/></Grid></TabItem>
<TabItem Header="Analysis"><Grid Margin="8"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><StackPanel><StackPanel Orientation="Horizontal"><Button Name="Analyze" Content="Analyze Badmail" Margin="4" Padding="14,6"/><Button Name="AD" Content="Validate AD" Margin="4" Padding="14,6"/><Button Name="EXO" Content="Validate Exchange Online" Margin="4" Padding="14,6"/></StackPanel><StackPanel Orientation="Horizontal" Margin="4,0,4,5"><TextBlock Text="AD validation: " FontWeight="SemiBold"/><TextBlock Name="ADValidationState" Text="Not Run" Margin="0,0,24,0"/><TextBlock Text="Exchange Online validation: " FontWeight="SemiBold"/><TextBlock Name="EXOValidationState" Text="Not Run"/></StackPanel></StackPanel><DataGrid Name="Results" Grid.Row="1" Margin="4" AutoGenerateColumns="True" IsReadOnly="True"/><TextBlock Name="Summary" Grid.Row="2" Margin="4" FontWeight="SemiBold"/></Grid></TabItem>
<TabItem Header="Remediation"><DataGrid Name="Remediation" Margin="8" AutoGenerateColumns="False" IsReadOnly="True"><DataGrid.Columns><DataGridTextColumn Header="Origin" Binding="{Binding OriginHost}" Width="150"/><DataGridTextColumn Header="Origin IP" Binding="{Binding OriginIP}" Width="120"/><DataGridTextColumn Header="Type" Binding="{Binding OriginType}" Width="150"/><DataGridTextColumn Header="Recipient" Binding="{Binding FailedRecipient}" Width="190"/><DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="170"/><DataGridTextColumn Header="AD" Binding="{Binding ADStatus}" Width="100"/><DataGridTextColumn Header="EXO" Binding="{Binding EXOStatus}" Width="100"/><DataGridTextColumn Header="Recommended remediation" Binding="{Binding Remediation}" Width="*"/></DataGrid.Columns></DataGrid></TabItem>
<TabItem Header="Reports / Archive"><StackPanel Margin="12"><Button Name="Report" Content="Export HTML + CSV Report" Width="240" Padding="10" Margin="4" HorizontalAlignment="Left"/><Button Name="Archive" Content="Archive Badmail (No Delete)" Width="240" Padding="10" Margin="4" HorizontalAlignment="Left"/><TextBlock Name="Output" Margin="4,12" TextWrapping="Wrap"/></StackPanel></TabItem>
</TabControl><StatusBar Grid.Row="2"><StatusBarItem><TextBlock Name="Status" Text="Ready"/></StatusBarItem><Separator/><StatusBarItem><TextBlock Text="v1.0.0"/></StatusBarItem></StatusBar></Grid></Window>
'@
$reader=New-Object Xml.XmlNodeReader $x;$w=[Windows.Markup.XamlReader]::Load($reader)
$script:UI=@{}
foreach($n in 'Tabs','Server','Discover','Path','Browse','AltCred','Prereq','RefreshPre','InstallPre','Analyze','AD','EXO','Results','Summary','Remediation','Report','Archive','Output','Status','ADValidationState','EXOValidationState'){
 $script:UI[$n]=$w.FindName($n)
 if($null -eq $script:UI[$n]){throw "Required WPF control '$n' was not found."}
}
$Tabs=$script:UI.Tabs;$Server=$script:UI.Server;$Discover=$script:UI.Discover;$Path=$script:UI.Path;$Browse=$script:UI.Browse;$AltCred=$script:UI.AltCred
$Prereq=$script:UI.Prereq;$RefreshPre=$script:UI.RefreshPre;$InstallPre=$script:UI.InstallPre;$Analyze=$script:UI.Analyze;$AD=$script:UI.AD;$EXO=$script:UI.EXO
$ResultsGrid=$script:UI.Results;$SummaryText=$script:UI.Summary;$ADValidationState=$script:UI.ADValidationState;$EXOValidationState=$script:UI.EXOValidationState;$RemediationGrid=$script:UI.Remediation;$ReportButton=$script:UI.Report;$ArchiveButton=$script:UI.Archive;$OutputText=$script:UI.Output;$StatusBarText=$script:UI.Status
function Refresh-Views {$rows=@($script:Rows);$ResultsGrid.ItemsSource=$null;$ResultsGrid.ItemsSource=$rows;$RemediationGrid.ItemsSource=$null;$RemediationGrid.ItemsSource=$rows;$u=@($rows|Where-Object {$null -ne $_ -and $_.FailedRecipient}|ForEach-Object {$_.FailedRecipient}|Sort-Object -Unique).Count;$g=($rows|Where-Object {$null -ne $_}|Group-Object Category|ForEach-Object {$_.Name+': '+$_.Count}) -join ' | ';$script:UI['Summary'].Text='Messages: '+$rows.Count+' | Unique recipients: '+$u+' | '+$g}
function Show-Error($e){$msg=[string]$e;if($_ -and $_.ScriptStackTrace){$msg += [Environment]::NewLine+[Environment]::NewLine+'Stack:'+[Environment]::NewLine+$_.ScriptStackTrace};Write-AppLog $msg 'ERROR';[Windows.MessageBox]::Show($msg,'IIS SMTP Badmail Analyzer',[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Error)|Out-Null}
$RefreshPre.Add_Click({try{$Prereq.ItemsSource=@(Get-PrerequisiteState)}catch{Show-Error $_.Exception.Message}})
$InstallPre.Add_Click({$s=$Prereq.SelectedItem;if(-not $s){return};if([Windows.MessageBox]::Show('Install '+$s.Requirement+'?','Confirm',[Windows.MessageBoxButton]::YesNo)-ne 'Yes'){return};try{$script:UI['Status'].Text='Installing...';Install-Prerequisite $s.Requirement;$Prereq.ItemsSource=@(Get-PrerequisiteState)}catch{Show-Error $_.Exception.Message}finally{$script:UI['Status'].Text='Ready'}})
$Discover.Add_Click({try{$script:Server=$script:UI['Server'].Text.Trim();if(-not $script:Server){throw 'Enter an SMTP server.'};if($AltCred.IsChecked){$script:Credential=Get-Credential};$f=@(Find-IisSmtpBadmail $script:Server);if(-not $f.Count){throw 'No IIS SMTP mailroot was discovered. Enter or browse to Badmail manually.'};$script:UI['Path'].Text=$f[0].Badmail;$script:Badmail=$f[0].Badmail}catch{Show-Error $_.Exception.Message}})
$Browse.Add_Click({$d=New-Object Windows.Forms.FolderBrowserDialog;$d.Description='Select IIS SMTP Badmail';if($d.ShowDialog() -eq 'OK'){$script:UI['Path'].Text=$d.SelectedPath}})
$Analyze.Add_Click({try{$script:UI['Status'].Text='Analyzing...';$script:Badmail=$script:UI['Path'].Text.Trim();$script:Server=$script:UI['Server'].Text.Trim();if(-not $script:Server){$script:Server='Unknown'};$script:Rows=@(Invoke-BadmailAnalysis $script:Badmail);$ADValidationState.Text='Not Run';$EXOValidationState.Text='Not Run';Refresh-Views;$Tabs.SelectedIndex=1;Write-AppLog ('Analyzed '+$script:Rows.Count+' messages') 'PASS'}catch{Show-Error $_.Exception.Message}finally{$script:UI['Status'].Text='Ready'}})
$AD.Add_Click({if(-not $script:Rows.Count){return};try{$script:UI['Status'].Text='Validating AD...';Invoke-ADRecipientValidation $script:Rows $script:Credential;$ADValidationState.Text='Completed - '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Refresh-Views}catch{Show-Error $_.Exception.Message}finally{$script:UI['Status'].Text='Ready'}})
$EXO.Add_Click({if(-not $script:Rows.Count){return};if([Windows.MessageBox]::Show('PowerShell 7 will open for Exchange Online device authentication. Continue?','Exchange Online',[Windows.MessageBoxButton]::YesNo)-ne 'Yes'){return};try{$script:UI['Status'].Text='Validating Exchange Online...';Invoke-EXORecipientValidation $script:Rows;$EXOValidationState.Text='Completed - '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Refresh-Views}catch{Show-Error $_.Exception.Message}finally{$script:UI['Status'].Text='Ready'}})
$ReportButton.Add_Click({if(-not $script:Rows.Count){return};try{$r=Export-AnalyzerReport $script:Rows $script:Server $script:Badmail;$script:UI['Output'].Text='HTML: '+$r.Html+[Environment]::NewLine+'CSV: '+$r.Csv;Start-Process $r.Html}catch{Show-Error $_.Exception.Message}})
$ArchiveButton.Add_Click({if(-not $script:Badmail){return};$c=@(Get-ChildItem $script:Badmail -File|Where-Object Extension -in '.BAD','.BDR','.BDP').Count;if([Windows.MessageBox]::Show([string]$c+' files will be COPIED to ZIP. Source files will not be deleted. Continue?','Archive',[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Warning)-ne 'Yes'){return};try{$z=New-BadmailArchive $script:Badmail $script:Server;$script:UI['Output'].Text='Archive: '+$z}catch{Show-Error $_.Exception.Message}})
$Prereq.ItemsSource=@(Get-PrerequisiteState);Write-AppLog 'Application started';[void]$w.ShowDialog()
