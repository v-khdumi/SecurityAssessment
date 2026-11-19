# Azure Tenant Assessment with Microsoft Foundry

This application reviews Azure configuration and security posture. It does not confirm or rule out a breach. The full assessment mandate is visible before a run. For an approved assessment, Foundry evaluates a minimal set of configuration indicators. The archive is handled on the company-approved assessment host, and no raw ZIP, identifiers, logs, or reports are sent to Foundry. The application makes no Azure or Foundry calls before approval.

## Run locally

Use Python 3.10 or later. No additional Python packages are required. Before loading an archive, choose an **existing, company-approved local directory** on an encrypted device. Restrict its permissions to the assessment team and make sure it does not sync to an external service. The application does not configure access controls for you.

Do not commit input archives, snapshots, credentials, or populated system mappings. The app does not bundle or substitute any evidence.

```powershell
python -B .\app.py --output 'C:\Company\AzureReview\Snapshots'
```

Open the loopback address printed in the terminal; do not share it. Configure the agents' Azure OpenAI connection in **Setup**, select your configuration ZIP, and choose **Review and confirm**. The app uses that ZIP as its only evidence source. It does not collect live Azure data or use an offline fallback.

Saving setup makes no cloud calls. **Configured; access not tested** means only that local settings are present.

Each completed run writes a dated directory containing `report.html` (self-contained, with tabs, searchable tables, and light/dark themes), `snapshot.json`, and `csv\<area>\`. The upload is streamed to a temporary file in the approved local directory, closed and removed after parsing, and not included in the snapshot. An archive without supported configuration evidence stops the assessment rather than producing a clean report.

The report's **Executive summary** states what Foundry found, the first action, the archive scope, and which evidence was insufficient or unavailable. It is also exported to `csv\summary\executive-summary.csv`. **Open full report** opens a separate page, and **Open all findings** jumps to searchable cards. Expand **Evidence and remediation plan** to see the observed value and source, corroborating and missing settings, severity rationale, suggested owners, and control-specific verification, change planning, and closure criteria. The same guidance is included in `csv\findings\details.csv`.

Each report tab includes a **Review and closure checklist** for the relevant domain. Technical tabs also show per-resource **Configuration evidence and gaps** and findings linked to the same scope. The grouped inventory, RBAC assignment summary, benchmark status, and billing reconciliation offer additional breakdowns without inferring access or compliance. **Not observed** does not mean disabled, absent, or passed. Graph observations and optional AI prompts are separate from configuration findings, and the report does not apply or validate remediation.

Each finding links directly to the relevant **Microsoft Learn** procedures. Each tab also includes scope-specific links with a short explanation of what to verify. **Security posture** explains how to interpret the supplied Entra settings before showing the underlying Graph rows. Reference URLs come from a fixed public Microsoft Learn catalog, not the uploaded archive or AI responses. They are exported to CSV and load only when clicked; the report opens them without sending its own URL as a referrer.

**Assessment progress** shows upload, ZIP validation, evidence preparation, each AI agent's response, and report creation. If a run stops, the error is shown in that panel. A validated ZIP is readable, but it does not necessarily contain supported settings. If the run stops before either agent starts, check that the export contains configuration from a supported source. The app does not fall back to an offline result.

After opening the report from the app, select **Clean** next to **Toggle theme** to return to the ZIP upload and clear the matching workspace. Saved reports and Foundry setup stay in place. Select a ZIP and confirm again to start another assessment. The button is hidden in HTML reports opened as local files.

## Run on a managed assessment host

Use this deployment when the workstation must not process the contents of the archive. Run the application on a company-managed host approved to receive the ZIP and store reports, not on the workstation. The workstation browser uploads the archive and displays the report. The host decompresses and validates the ZIP, prepares the allowlisted indicators, and writes the report. The approved Foundry deployment makes the assessment decisions. Do not send unfiltered archive contents directly to Foundry.

On the approved Windows host, from the application directory, start the app on its existing loopback binding:

```powershell
python -B .\app.py --port 8765 --output 'C:\Company\AzureReview\Snapshots'
```

For single-user access, use authorized SSH port forwarding if your organization permits it, with port `8765` available on the workstation. Replace the example account and host with the approved ones. Use the same port on both sides so the application's Host and Origin checks continue to work:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8765:127.0.0.1:8765 'approved-account@approved-assessment-host'
```

Keep the tunnel open and use the exact session URL printed by the application, including its random path. Do not bind the Python server to a public interface. Set an approved local output directory on the managed host and use **Setup** to configure the approved Foundry deployment. Downloading or printing the report is a separate action that creates a copy on the workstation.

## Accepted ZIP format

The host checks `.json` files in the ZIP, including subfolders, and identifies supported configuration by its structure and fields. The names below are examples; files do not need to be renamed. Only supported configuration contributes to the assessment. Unsupported or malformed JSON is counted as skipped, except that invalid JSON in a file with a documented example name fails explicitly. Checksums, error files, and folders or files identified as sign-in, audit, or application logs are skipped without being opened. An export error can still mean that required configuration is missing.

Include one document per tenant configuration type. Individual Teams responses can be spread across multiple JSON files. For Conditional Access, include the original Graph metadata or full policy objects with `id`, `state`, and `conditions` so the importer can distinguish them from other lists. One Azure inventory in the documented normalized format is supported. Limits: 512 MiB per archive, 4,000 entries, 32 MiB per JSON file checked, and 64 MiB across JSON files checked (uncompressed). For larger exports, split by assessment scope rather than splitting the bytes of a ZIP.

| Entry | Accepted evidence |
|---|---|
| `authorizationPolicy.json` | Graph `/policies/authorizationPolicy`: guest invitations and selected default member permissions. |
| `authenticationMethodsPolicy.json` | Graph `/policies/authenticationMethodsPolicy`: supported method types and configuration states, not registrations for individuals. |
| `conditionalAccessPolicies.json` | One Graph page `{"value": [...]}` from `/identity/conditionalAccess/policies`: counts by state only. It does not determine MFA coverage. The app does not follow `nextLink`. |
| `sharepointSettings.json` | [Graph `/admin/sharepoint/settings`](https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0): selected SharePoint and OneDrive tenant settings. Accepts the settings object directly or inside `{"value": {...}}`. |
| `teamsConfiguration.json` | A [Graph `GET /teams/{team-id}`](https://learn.microsoft.com/en-us/graph/api/team-get?view=graph-rest-1.0) response containing `id` and `guestSettings`, or `{"value": [...]}` wrapping those individual responses. The bulk `/teams` list by itself does not supply these settings. |
| `assessment-v1.json` | Locally normalized configuration inventory, RBAC, optional function metadata, and approved aggregates. |
| `prowler-summary.json` | Normalized summary of a separately authorized Prowler run. Do not include an unredacted Prowler export, resource identifiers, alert entities, or descriptions. |
| `prowler-cis-azure.json` / `prowler-nis2-azure.json` | Optional official Azure framework JSON catalogs from your approved Prowler release. The app imports requirement IDs, not descriptions. Requirements without results stay `manual_review / not_run`. |

Microsoft 365 exports can be uploaded without Azure inventory. The **Microsoft 365** tab shows observed settings and Foundry decisions. Teams' original IDs and names, SharePoint sharing domain lists, emails, chat messages, files, and audit events are not sent to Foundry or included in the report. An absent setting is not a pass. Other Microsoft 365 workloads, such as Exchange Online, are not assessed by these adapters. The app does not call Microsoft Graph directly.

Example `assessment-v1.json` (synthetic):

```json
{
  "schema_version": 1,
  "resources": [
    {
      "id": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/sample/providers/Microsoft.Web/sites/sample",
      "type": "microsoft.web/sites",
      "location": "westeurope",
      "httpsOnly": false,
      "minTlsVersion": "1.2",
      "publicNetworkAccess": "Enabled"
    }
  ],
  "rbac": []
}
```

`subscriptions` and `groups` are optional arrays of subscription GUIDs and resource group ARM IDs. RBAC entries accept `scope`, `principalId`, `principalType`, and `roleDefinitionId`. Principal object IDs are retained without resolving them to identities. Other resource identifiers are pseudonymized. The configuration allowlist is in [evidence.py](./evidence.py). Unknown fields, unrestricted text, and personal identifiers are not reproduced.

Optional `functions` entries accept `id` (a function ARM ID, including any slot), `trigger`, `authLevel` (`anonymous`, `function`, or `admin`), and `disabled` (boolean). Do not include invocation URLs, full function definitions, files, or test data. The live collector does not call the Functions listing endpoint because it can return such fields. App inventory can also include `lastDeploymentDate`, `lastDeploymentStatus`, `lastBackupDate`, `runtimeStack`, `runtimeVersion`, and `runtimeEosDate`. Dates use `YYYY-MM-DD`; verify end-of-support dates with the vendor. The report computes the 120-day support window against the snapshot date. Do not include repository URLs, names, deployment messages, or backup copies.

Example `prowler-summary.json` (illustrative version and requirements):

```json
{
  "version": "6.1.0",
  "requirements": [
    {
      "benchmark": "CIS-Azure",
      "benchmarkVersion": "6.0",
      "section": "1",
      "requirement": "1.2",
      "exclusion": "entra_permissions"
    }
  ],
  "checks": [
    {
      "benchmark": "NIS2-2024-2690",
      "section": "2",
      "requirement": "2.1",
      "status": "fail",
      "point": "b"
    }
  ]
}
```

Allowed statuses: `pass`, `fail`, `manual_review`, `needs_entra_access`, and `not_applicable`. Allowed exclusions: `not_run`, `privacy`, `data_plane`, `entra_permissions`, `not_supported`, and `scope`. A catalog entry does not prove a check was run. The DPO and legal team should verify mappings from the implementing regulation to Article 21(2).

## Standalone Azure collector (optional, outside the web app)

Install Azure CLI from an approved source. Set the assessment tenant GUID locally. Use a dedicated approved CLI profile, for example by setting `AZURE_CONFIG_DIR` to a protected profile directory. Azure CLI may keep its own token cache there; the application does not copy credentials or tokens into the snapshot. The application never invokes `az login`, changes the default subscription, installs extensions, or calls Microsoft Graph live.

For the first authorized collector run, use `--subscription-id` in the terminal command below to limit collection to a test subscription. The collector fails rather than falling back to another subscription if the selected subscription is not visible. Omit `--subscription-id` to review the tenant's enabled subscriptions visible to the dedicated CLI session. Reader at the tenant root does not prove that the local session's subscription list is complete or current.

The collector projects Resource Graph metadata, reads generic ARM resource lists and RBAC assignments, and flags resources present in only one inventory. Where available, it adds cost by group and currency for the previous UTC calendar month, Defender and Azure Policy aggregates, and 30-day totals for `Requests`, `Http4xx`, and `Http5xx` for up to 100 observed sites/slots. Active alerts are counted by severity without retrieving entities and descriptions. Assignment parameters and diagnostic events are not collected. App Service detail adds dedicated ARM GETs for FTP/SCM publishing policies (booleans, not credentials), presence of diagnostic settings, and sticky setting name counts at the parent site. It does not save the names or read setting values. The `Method and limits` tab shows coverage and sanitized command templates. Resource Graph and Cost Management use POST for documented read-only queries; the collector performs no remediation.

### Standalone terminal commands (local reports)

Only run these after reviewing the mandate and approving the data categories:

```powershell
python -B .\build.py --zip 'C:\Company\AzureReview\config.zip' --output 'C:\Company\AzureReview\Snapshots' --confirm
python -B .\azure_collect.py --tenant-id '<assessment-tenant-GUID>' --subscription-id '<test-subscription-GUID>' --output 'C:\Company\AzureReview\Snapshots' --confirm-read-only
```

[scripts/collect.sh](./scripts/collect.sh) offers the same live flow on Bash.

## AI review setup (API key)

In **Setup**, enter the Azure OpenAI resource endpoint (for example `https://<resource>.openai.azure.com`), the **deployment name** shown in the portal (for example `review-model-1.2`), and its API key. Use a company-approved deployment that supports the [Azure OpenAI Responses API](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses) and permits API key authentication. Do not use a Foundry project URL ending in `/api/projects/...`.

The **Security Posture** and **Compliance** agents are included in the application and use that one deployment. There is nothing to create in the Foundry portal besides the deployment if you do not already have one. They are not hosted Foundry Agent Service agents: [that service requires Entra and does not accept API keys](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/configure-agent).

Settings entered via the UI exist only in the running local process. The API key is masked, never returned or written to disk, and cleared when the app stops. A blank key keeps the existing key only for the same endpoint. Do not send the key in chat. Saving does not validate the credentials against Azure. For a real assessment, the app calls each agent for its supported evidence after approval: Security Posture reviews Azure resource settings, and Compliance reviews supported Entra and Microsoft 365 configuration from Graph. An agent without evidence is marked not called. Agent failures or incomplete model responses stop the assessment; there is no local fallback.

Responses requests use `store: false`. Managed telemetry policies may still apply. Each request sends selected boolean or enumerated configuration fields, public control criteria, and temporary row numbers to the approved deployment. The allowlist includes a zero/nonzero HTTP usage indicator, not raw request counts. The request excludes the archive, policy and resource names, resource and principal IDs, locations, costs, text from the archive, and all reports. Approve both the deployment and this transfer before processing real evidence. If organizational policy forbids the transfer, do not approve it.

Foundry decides `finding`, `no_finding`, or `insufficient` for each distinct control and setting value, and supplies severity for findings. Identical control values share the same model decision, which the app maps back to every matching resource in the upload. The app validates the response format, attaches local pseudonymous evidence and fixed Microsoft Learn guidance, and applies the separate report severity uplift for systems marked as likely to process personal data. **Findings → Foundry evidence decisions** records model decisions. Imported billing, inventory, and compliance summaries remain context; missing or unsupported data is not AI-verified. The standalone build and collector commands still use local rules and are labelled separately.

**Method and limits → Foundry request receipts** and `csv\method-and-limits\foundry-receipts.csv` record each completed response's UTC timestamp, round-trip time, HTTP status, and pattern count. The provider-reported model, request/response IDs, and input/output tokens are shown when Azure returns them. These are local records, not a second query to Azure or proof of tenant-wide coverage. Existing reports are not modified; receipts are available only for new runs.

## Acceptance, retention, and limitations

- **Acceptance:** Approve an assessment using your own authorized configuration ZIP and deployment. Verify agent statuses in `Method and limits` and compare the executive summary to `Findings → Foundry evidence decisions`. Do not treat syntax checks or mock responses as live validation.
- **Systems:** The app suggests groupings within a subscription by stripping environment markers from group names in memory. Confirm the suggestions in `csv\resource-groups\system-map-candidates.csv` and copy approved rows to [scripts/system_map.csv](./scripts/system_map.csv). Use only `SYS-...` codes, not names. A `yes` classification raises severity by one level up to `High`. To correlate runs, keep a randomly generated 64-digit hexadecimal `ASSESSMENT_PSEUDONYM_KEY` within the assessment team, outside source and reports. Otherwise aliases change on each run.
- **Retention:** The proposed retention period is 30 days, subject to DPO approval. For one snapshot, use `python -B .\build.py --output 'C:\Company\AzureReview\Snapshots' --delete-snapshot '<snapshot-id>' --confirm`. This is logical deletion, not media sanitization or backup deletion. Apply retention separately to the source export.
- **Coverage:** App Service and other inventory areas show available configuration evidence only. No raw application settings, credential values, callback URLs, repository/deployer identities, or deployment logs are read. Reachability, effective RBAC, incident activity, and restore outcomes are not established. Each finding requires owner confirmation before action.
- **Prowler:** This app imports official catalogs and normalized results; it does not launch a live scan. The [Prowler Azure authentication guide](https://docs.prowler.com/user-guide/providers/azure/authentication) lists permissions such as `AuditLog.Read.All` and `Directory.Read.All` for Entra checks. Reader does not cover the full benchmark, and the mandate excludes reading event logs. Before a separate run, approve the version, exact checks, API calls, privileges, and exclusions. Do not grant additional access just to make the report complete.
- **Compliance and breach status:** The report is not a CIS, NIS2, GDPR, or DORA verdict. Use the organization's SOC/CSIRT process for a suspected active breach. Reviewing event logs would require a separately authorized workflow; do not disable the import safeguards.

Run local verification without signing in or contacting Azure or Foundry:

```powershell
python -B -m unittest discover -s .\tests -v
```
