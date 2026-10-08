# IIS SMTP Badmail Analyzer

A Windows PowerShell/WPF utility for analyzing Microsoft IIS SMTP Badmail, correlating `.BAD`, `.BDR`, and `.BDP` files, validating recipients, and producing remediation-focused HTML and CSV reports.

## Goals

- Generic across IIS SMTP environments. No organization, domain, server, path, or recipient is hardcoded.
- Read-only analysis by default.
- Stream large `.BAD` files instead of loading complete messages into memory.
- Keep original-delivery failures separate from secondary NDR-delivery failures.
- Validate recipients against Active Directory and Exchange Online when requested.
- Treat unavailable validation as **Not Checked**, never as **Not Found**.
- Offer prerequisite installation instead of silently changing the workstation.
- Keep credentials in memory only.
- Generate self-contained HTML reports with evidence and recommended remediation.
- Archive Badmail only after explicit operator confirmation. v1.0 does not delete Badmail.

## Requirements

- Windows PowerShell 5.1 for the WPF GUI.
- Windows with .NET/WPF.
- Administrative access to the target SMTP server's mailroot when remote discovery uses administrative shares.
- Optional: RSAT Active Directory PowerShell module.
- Optional: PowerShell 7 and ExchangeOnlineManagement for Exchange Online validation.

The application checks these prerequisites at startup and offers installation guidance/actions for optional components.

## Start

Run Windows PowerShell as an account that can read the SMTP server, then:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\IIS-SMTP-Badmail-Analyzer.ps1
```

The application asks for the SMTP server. It attempts to discover the IIS SMTP mailroot through common local/remote locations and allows a manual Badmail path when discovery is not possible.

## Workflow

1. Review prerequisites.
2. Enter the SMTP server.
3. Select current Windows credentials or alternate credentials.
4. Discover or manually select the Badmail directory.
5. Analyze Badmail.
6. Optionally validate unique recipients against Active Directory.
7. Optionally validate recipients against Exchange Online.
8. Review classifications and remediation.
9. Export HTML/CSV.
10. Optionally archive the current Badmail files.

## Safety

Analysis, discovery, AD validation, and Exchange Online validation are read-only.

Archive copies the current Badmail files into a ZIP archive after explicit confirmation. The source files are not deleted.

## Failure classifications

The analyzer recognizes common classes including:

- Recipient rejected / invalid recipient
- Message too large
- Exchange Online tenant attribution / TLS / relay failure
- Mailbox unavailable
- Temporary SMTP failure
- Malformed recipient address
- Other SMTP failure

Classification is evidence based. Directory validation augments SMTP evidence but does not replace it.

## Exchange Online

The GUI is Windows PowerShell 5.1/WPF. Exchange Online validation launches a temporary PowerShell 7 helper because current ExchangeOnlineManagement authentication is more reliable there. Authentication is interactive/device based. No Exchange Online password is stored.

## Output

By default, output is written below:

```text
%LOCALAPPDATA%\IIS-SMTP-Badmail-Analyzer\
    Logs\
    Reports\
    Archives\
```

Environment profiles may be saved later, but credentials must never be persisted.

## License

MIT. See [LICENSE](LICENSE).
