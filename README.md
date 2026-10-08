# IIS SMTP Badmail Analyzer

A single-file Windows PowerShell/WPF utility for analyzing Microsoft IIS SMTP Badmail, correlating `.BAD`, `.BDR`, and `.BDP` files, validating recipients, and producing remediation-focused HTML and CSV reports.

## Design

- One self-contained `IIS-SMTP-Badmail-Analyzer.ps1`; no runtime modules.
- Generic across IIS SMTP environments; no organization, domain, server, path, IP address, or recipient is hardcoded.
- Read-only Badmail analysis by default.
- Streams large `.BAD` files rather than loading complete messages into memory.
- Keeps original-delivery failures separate from secondary NDR-delivery failures.
- Optional Active Directory and Exchange Online recipient validation.
- A failed/unavailable directory query must not be treated as recipient absence.
- Optional prerequisites are never installed silently.
- Credentials are not persisted by the application.

## Requirements

- Windows PowerShell 5.1 and WPF.
- Read access to the IIS SMTP Badmail directory.
- Optional: RSAT Active Directory PowerShell module.
- Optional: PowerShell 7 and ExchangeOnlineManagement for Exchange Online validation.

## Deployment

Copy the single `IIS-SMTP-Badmail-Analyzer.ps1` file to the administrative workstation. No companion module directory is required.

## Authentication and data handling

Alternate Windows credentials, when requested, are held only by the running PowerShell process and are not exported by the application.

Exchange Online validation uses interactive device authentication through ExchangeOnlineManagement. The analyzer does not export or deliberately persist Exchange Online authentication tokens. Authentication/token lifecycle outside the analyzer is controlled by Microsoft's ExchangeOnlineManagement authentication stack.

Temporary Exchange Online helper files are created beneath the user's temporary directory and removed when validation completes or fails.

The analyzer does not include telemetry or upload analysis data to an external service.

## Local output

Operational data is intentionally written beneath:

```text
%LOCALAPPDATA%\IIS-SMTP-Badmail-Analyzer\
    Logs\
    Reports\
    Archives\
```

Logs contain application activity and error information. HTML/CSV reports can contain mail metadata such as recipients, message subjects, originating hosts/IP addresses, SMTP diagnostics, and validation results.

Archive is optional and requires confirmation. An archive contains copies of the selected `.BAD`, `.BDR`, and `.BDP` files and may therefore contain original message content or attachments. Source Badmail files are not deleted.

Treat reports and archives according to the organization's information-handling requirements.

## Start

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\IIS-SMTP-Badmail-Analyzer.ps1
```

## Workflow

1. Review prerequisites.
2. Enter the SMTP server.
3. Discover or manually select the Badmail directory.
4. Analyze Badmail.
5. Optionally validate recipients against Active Directory.
6. Optionally validate recipients against Exchange Online.
7. Review origin, classifications, evidence, and remediation.
8. Optionally export HTML/CSV.
9. Optionally archive the current Badmail files.

## Validation semantics

Recipient states are:

- `Not Checked`
- `Found`
- `Not Found`
- `Error/Unavailable`

`Not Found` is reserved for a successful directory query that returned no matching recipient. Authentication, connectivity, module, or service failures must not be converted into `Not Found`.

## License

MIT. See `LICENSE`.
