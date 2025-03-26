# Scenario
Echelon Zero is a defense industrial base partner that specializes in software development. An intelligence community partner has sent an alert on the possibility of Gh0st RAT malware communications from the corporate network to a potentially malicious C2 domain associated with APT41.

APT41 is a state-sponsored Chinese cyber espionage operation. Gh0st RAT (remote access Trojan) was publicly released in 2008 and despite its age continues to be used in breaches.

The notification has prompted an investigation of the Echelon Zero network. You need to search for evidence of compromise. Your goal is to create a detailed timeline of activity that the threat actor performed on the compromised network. The timeline should include artifact logs beyond what is required to answer questions asked in this challenge. Artifacts may include malicious domain names, compromised user accounts, filenames, malicious processes, and malicious service names.
The IP address of the internal host infected with **Gh0st RAT** malware is `172.16.6.104`.
# Environment
A network diagram is attached is shown below.

The analysis environment consists of a *Sift forensics* workstation and a *Splunk instance*. Echelon Zero provided Windows Event logs and Sysmon logs from all of the *Windows devices in its netw*ork. These logs have been ingested into the Splunk instance. Echelon Zero also provided the raw logs from its web proxy, as well as a full packet capture that was collected at the network edge and data center subnets (illustrated in the network diagram).

**Splunk:**
- `HTTP://199.63.64.120:8000`
- Username: `Admin`
- Password: `simspace1`

For convenience, the Firefox homepage has been configured to open the Splunk search app with the timeframe pre-set to **June 22, 2023**, which is the timeframe of logs provided in Splunk.

![[ee573ffd-e3ed-485d-9939-fd526ce2fffc.png]]


NEXT: [[Question 1]]

-----------------------------
A process tree can show not only how the malicious process was executed, but also what actions were performed by it.

## Explanation^
The name of the malicious executable (`OutlookSharing.exe`) can be used to investigate the infected host and find running processes that communicated with the external IP address. With the external IP address and the hostname, the process tree can be systematically investigated to get to the executable downloaded by Gh0st RAT.
# Identifying the Malicious Executable

The following Splunk query searches for Sysmon network connection events on `acc-win10-4` that connect to the identified external IP address `119.28.139.120`:
```
index=windows host=acc-win10-4 EventCode=3 DestinationIp=119.28.139.120
```

The query identifies an executable named `svchost_console.exe`. It also shows that the process is being run by the user `ez\roxanne.farley`.
The following Splunk query shows child processes initiated by the `svchost_console.exe` as well as the user `ez\roxanne.farley`:
```
index=windows host="acc-win10-4" EventCode=1 User="ez\\roxanne.farley" ParentImage="C:\\Users\\roxanne.farley\\AppData\\Local\\Temp\\svchost_console.exe"
```

The query shows two instances of the child process `C:\windows\SysWOW64\cmd.exe` executed by `svchost_console.exe`. 

Investigate child processes initiated by `C:\windows\SysWOW64\cmd.exe` and the user `ez\roxanne.farley`:

```
index=windows host="acc-win10-4" EventCode=1 User="ez\\roxanne.farley" ParentImage="C:\\Windows\\SysWOW64\\cmd.exe"
```

The query shows one instance of `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` with PID `5156` in this process tree.

The following Splunk query identifies child processes initiated by `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` with PID `5156`:

```
index=windows host="acc-win10-4" EventCode=1 User="ez\\roxanne.farley" ParentImage="C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" ParentProcessId=5156
```

The query shows that the child process `powershell.exe` executed a file in the following user path:

```
C:\Users\roxanne.farley\AppData\Local\Microsoft\Outlook\OutlookSharing.exe
```

## Analyst Insight

Additionally, searching for **Sysmon Event ID 11** associated with this path and file reveals that the executable was created by the same PowerShell process with PID `5156`:

```
index=windows EventCode=11 TargetFilename="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe"
```

--------------------------------
# Question 3

Enter the original filename of the executable downloaded by Gh0st RAT.
## Background
The process tree investigation showed that the Gh0st RAT executable `svchost_console.exe` spawned `cmd.exe`, which spawned `powershell.exe`, which eventually executed the new executable `OutlookSharing.exe`. Investigation of file creation events shows that `OutlookSharing.exe` was also created by the same `powershell.exe` process that executed it. Since PowerShell created and executed `OutlookSharing.exe`, it is useful to take a closer look at the `powershell.exe` process. Investigating network connections made by malicious processes is just as important as investigating its child processes and spawned commands.

This investigation phase requires correlation of multiple event types such as Sysmon network connection logs with Squid proxy logs, or Zeek logs.
# Explanation 

# Finding the Original Filename
The following Splunk query shows Sysmon network connection events spawned by `roxanne.farley` and PowerShell with PID `5156`:﻿

```
index=windows host="acc-win10-4" EventCode=3 User="ez\\roxanne.farley" Image="C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" ProcessId=5156
```

The query reveals that the PowerShell process initiated a network connection but, unlike the Gh0st RAT communication, it was not directly to the internet. Instead it was routed through the proxy. The ability of a program to use or not use the configured proxy is known as being "proxy aware". Proxy aware processes should reach out to the internet through the proxy. Searching for events where a process communicates directly to an external IP address may overlook connections that go through the proxy. Therefore, it is necessary to correlate local network connection logs with corresponding events on the proxy server or network security monitor logs.

One way to correlate this Sysmon connection log with the corresponding proxy log entry is to identify the source port used for this communication and then use that to craft a query against the Squid proxy log. In this case, the source host of the communication is `172.16.6.104` and the source port used was `65374`. 

The following Splunk query shows the proxy log entry associated with the interesting network traffic:﻿

```
index=linux sourcetype="squid:access:recommended" src_ip=172.16.6.104 src_port=65374
```

The query returns a single log entry with valuable pieces of information in it. First, the URL provides the original filename of the executable which is `RURAL_HEAT.exe`. It also provides a new malicious external IP address of `66.42.98.220` with an associated hostname of `www.dylerays.tk`.
## Analyst Insight
﻿An interesting piece of intelligence can also be gathered from this information. It seems that the attacker did not rename their executable to `OutlookSharing.exe` before hosting it for download. Instead they downloaded the original file and saved it as `OutlookSharing.exe` in an attempt to blend in on the target system. The format of the original filename is interesting because it matches the naming convention for default payloads that are generated by Sliver, which is an open source C2 framework used for pentesting and adversary emulation.
﻿
----------------------------------------------------
# Question 4
Enter the name of the registry key value that was created for user persistence.
## Background
The following activity has been identified:
- Host `acc-win10-4` is infected with a Gh0st RAT executable named `svchost_console.exe` which was connected to `119.28.139.120`
- The Gh0st RAT malware spawned child processes, `cmd.exe` and `powershell.exe` which then connected to `www.dylerays.tk` (`66.42.98.220`) to download an executable named `RURAL_HEAT.exe` which was saved locally as `C:\Users\roxanne.farley\AppData\Local\Microsoft\Outlook\OutlookSharing.exe`
- The PowerShell process was used to execute `OutlookSharing.exe`

These artifacts and evidence are useful for creating hypotheses. For example, based on this activity, it is likely that the initial Gh0st RAT callback was used to download and execute a more robust Sliver C2 payload to be used by the attacker to complete additional actions on objective. Therefore, a good next step in the investigation is to determine what activity was spawned by `OutlookSharing.exe` on host `acc-win10-4`.

## Explanation
## Detecting Registry Run Keys

The following Splunk query searches for processes spawned by `OutlookSharing.exe`:
```
index=windows EventCode=1 ParentImage="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe"
```

The Splunk query below provides a list of commands run by `OutlookSharing.exe`. The "table" directive is used to make the output more readable.

```
index=windows EventCode=1 ParentImage="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe" | table _time CommandLine
```

The query shows that `OutlookSharing` was spawned by the following command at 12:05:15:
```
reg add HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run /t REG_SZ /v OutlookSharing /d C:\Users\roxanne.farley\Appdata\Local\Microsoft\Outlook\OutlookSharing.exe
```

Searching for registry modification events in this time frame can verify if the command was successful creating the registry entry. The following Splunk query shows events at or near June 22, 2013 12:05:15 to identify the registry creation event:
```
index=windows host=acc-win10-4 EventCode=13
```

The result of the query reveals that the attacker's registry command was indeed successful. A new entry was created in `HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run` which is a well known Auto Start Extensibility Points (ASEP) used by attackers for user persistence. Since this was written to HKEY Current User in `roxanne.farley`'s user context, the malicious file `OutlookSharing.exe` is executed every time `roxanne.farley` logs into the system.

## Analyst Insight

A registry key by itself is not necessarily an indicator of persistence. Windows is constantly writing and modifying registry entries as part of normal operation. The registry is massive, but there are a few registry hives that are well known ASEPs. ASEPs can be used to trigger process execution typically on boot or on user login.

A well known ASEP is `HKCU\SOFTWARE\MIcrosoft\Windows\CurrentVersion\Run`. The fact that a new registry key is created there that calls an executable that has already been identified as malicious (`OutlookSharing.exe`) is most definitely an indicator of persistence.