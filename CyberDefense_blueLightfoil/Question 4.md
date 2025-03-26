**Enter the name of the registry key value that was created for user persistence.**

Determine what activity was spawned by `OutlookSharing.exe` on `host` `acc-win10-4`.
## Background
The following activity has been identified:
- Host `acc-win10-4` is infected with a Gh0st RAT executable named `svchost_console.exe` which was connected to `119.28.139.120`
- The Gh0st RAT malware spawned child processes, `cmd.exe` and `powershell.exe` which then connected to `www.dylerays.tk` (`66.42.98.220`) to download an executable named `RURAL_HEAT.exe` which was saved locally as `C:\Users\roxanne.farley\AppData\Local\Microsoft\Outlook\OutlookSharing.exe`
- The PowerShell process was used to execute `OutlookSharing.exe`

These artifacts and evidence are useful for creating hypotheses. For example, based on this activity, it is likely that the initial Gh0st RAT callback was used to download and execute a more robust Sliver C2 payload to be used by the attacker to complete additional actions on objective. Therefore, a good next step in the investigation is to determine what activity was spawned by `OutlookSharing.exe` on host `acc-win10-4`.
# Detecting Registry Run Keys
The following Splunk query searches for processes spawned by `OutlookSharing.exe`:

```
index=windows EventCode=1 ParentImage="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe"
```

The Splunk query below provides a list of commands run by

`OutlookSharing.exe`. The "table" directive is used to make the output more readable.

```
index=windows EventCode=1 ParentImage="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe" | table _time CommandLine
```

The query shows that `OutlookSharing` was spawned by the following command at 12:05:15:

```
reg add HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run /t REG_SZ /v OutlookSharing /d C:\Users\roxanne.farley\Appdata\Local\Microsoft\Outlook\OutlookSharing.exe
```

Searching for registry modification events in this time frame can verify if the command was successful creating the registry entry. The following Splunk query shows events at or near June 22, 2013 12:05:15 to identify the registry creation event:

```
index=windows host=acc-win10-4 EventCode=13 outlooksharing
```

The result of the query reveals that the attacker's registry command was indeed successful. A new entry was created in `HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run` which is a well known Auto Start Extensibility Points (ASEP) used by attackers for user persistence. Since this was written to HKEY Current User in `roxanne.farley`'s user context, the malicious file `OutlookSharing.exe` is executed every time `roxanne.farley` logs into the system.

## Analyst Insight

A registry key by itself is not necessarily an indicator of persistence. Windows is constantly writing and modifying registry entries as part of normal operation. The registry is massive, but there are a few registry hives that are well known ASEPs. ASEPs can be used to trigger process execution typically on boot or on user login.

A well known ASEP is `HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run`. The fact that a new registry key is created there that calls an executable that has already been identified as malicious (`OutlookSharing.exe`) is most definitely an indicator of persistence.

NEXT: [[Question 5]]
