function Read-BadMessage {
 param([string]$Path,[int64]$MaxScanBytes=8388608)
 $r=[ordered]@{OriginalFrom=$null;OriginalTo=$null;Subject=$null;FailedRecipient=$null;Status=$null;Diagnostic=$null;TopFrom=$null;TopTo=$null;TopSubject=$null}
 $fs=[IO.File]::Open($Path,'Open','Read','ReadWrite');$sr=New-Object IO.StreamReader($fs,$true)
 try{$bytes=0;$dsn=$false;while(-not $sr.EndOfStream -and $bytes -lt $MaxScanBytes){$line=$sr.ReadLine();$bytes+=$line.Length+2
  if($line -match '^Final-Recipient:\s*(?:rfc822;)?\s*(.+)$'){$r.FailedRecipient=$matches[1].Trim();$dsn=$true}
  elseif($dsn -and $line -match '^Status:\s*(.+)$'){$r.Status=$matches[1].Trim()}
  elseif($dsn -and $line -match '^Diagnostic-Code:\s*(.+)$'){$r.Diagnostic=$matches[1].Trim()}
  elseif($r.Diagnostic -and $dsn -and $line -match '^\s+(.+)$'){$r.Diagnostic+=' '+$matches[1].Trim()}
  if($line -match '^From:\s*(.*)$'){if(-not $r.TopFrom){$r.TopFrom=$matches[1].Trim()}elseif(-not $r.OriginalFrom){$r.OriginalFrom=$matches[1].Trim()}}
  elseif($line -match '^To:\s*(.*)$'){if(-not $r.TopTo){$r.TopTo=$matches[1].Trim()}elseif(-not $r.OriginalTo){$r.OriginalTo=$matches[1].Trim()}}
  elseif($line -match '^Subject:\s*(.*)$'){if(-not $r.TopSubject){$r.TopSubject=$matches[1].Trim()}elseif(-not $r.Subject){$r.Subject=$matches[1].Trim()}}
  if($r.FailedRecipient -and $r.Diagnostic -and $r.OriginalFrom -and $r.Subject){break}
 }}finally{$sr.Dispose()}
 if(-not $r.OriginalFrom){$r.OriginalFrom=$r.TopFrom};if(-not $r.OriginalTo){$r.OriginalTo=$r.TopTo};if(-not $r.Subject){$r.Subject=$r.TopSubject}
 [pscustomobject]$r
}
function Read-BdpPrintable {param([string]$Path);if(-not(Test-Path $Path)){return ''};$fs=[IO.File]::OpenRead($Path);$sb=New-Object Text.StringBuilder;$run=New-Object Text.StringBuilder;try{while(($b=$fs.ReadByte()) -ne -1){if(($b -ge 32 -and $b -le 126) -or $b -in 9,10,13){[void]$run.Append([char]$b)}else{if($run.Length -ge 4){[void]$sb.AppendLine($run.ToString())};[void]$run.Clear()}};$sb.ToString()}finally{$fs.Dispose()}}
function Invoke-BadmailAnalysis {
 param([string]$BadmailPath)
 if(-not(Test-Path $BadmailPath)){throw 'Badmail path not found.'}
 foreach($bad in Get-ChildItem $BadmailPath -Filter '*.BAD' -File){
  $base=[IO.Path]::GetFileNameWithoutExtension($bad.Name);$bdp=Join-Path $BadmailPath ($base+'.BDP');$bdr=Join-Path $BadmailPath ($base+'.BDR')
  $h=Read-BadMessage $bad.FullName;$p=Read-BdpPrintable $bdp;$cat=Get-Classification $h.Status $h.Diagnostic $p $h.FailedRecipient
  $secondary=$null;if($p -match '([245]\d\d\s+[245]\.[0-9.]+[^\r\n]*)'){$secondary=$matches[1].Trim()}
  $o=[pscustomobject]@{Date=$bad.LastWriteTime;Source=$h.OriginalFrom;FailedRecipient=$h.FailedRecipient;OriginalTo=$h.OriginalTo;Subject=$h.Subject;Status=$h.Status;Category=$cat;Severity=$(if($cat -in 'Temporary SMTP Failure','Other'){'WARNING'}else{'FAIL'});ADStatus='Not Checked';EXOStatus='Not Checked';MessageSizeMB=[math]::Round($bad.Length/1MB,2);Diagnostic=$h.Diagnostic;SecondaryDiagnostic=$secondary;BaseName=$base;BAD=$bad.FullName;BDR=$(if(Test-Path $bdr){$bdr}else{$null});BDP=$(if(Test-Path $bdp){$bdp}else{$null});Remediation=''}
  $o.Remediation=Get-Remediation $o;$o
 }}
Export-ModuleMember -Function Read-BadMessage,Read-BdpPrintable,Invoke-BadmailAnalysis