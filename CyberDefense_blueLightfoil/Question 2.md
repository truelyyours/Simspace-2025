**Enter the name of the malicious executable downloaded and executed by Gh0st RAT.**

A process tree can show not only how the malicious process was executed, but also what actions were performed by it.
## Background

The internal host potentially infected with Gh0st RAT is `172.16.6.104`, and the host is communicating with `119.28.139.120`. Since Gh0st RAT is used by the attacker to download and execute a malicious file, the name of the malicious executable can be used to investigate the infected host and find running processes that communicated with the external IP address. Identifying the malicious process provides the investigator with the ability to identify other malicious activity by investigating the process tree. 

Splunk, however, identifies the source of log files by hostname rather than IP address, therefore it is necessary to first determine the hostname of the internal host `172.16.6.104`.

After the hostname is known, investigation of the malicious process tree can begin. Finding activity associated with the malicious process is an iterative task that requires several steps. First, **Sysmon Event ID 3** can be queried to find the process that communicated with the external IP `119.28.139.120`. Once that process has been identified, its **image name and process ID (PID)** can be used to query **Sysmon Event ID 1 logs**, which track process creation and command line activity. At that point, it is a matter of finding successive layers of child processes and PIDs.

## Identifying the Hostname

One option for identifying the hostname is to use the network diagram as a reference. The network diagram shows that the Windows workstation `acc-win10-4` is assigned `172.16.6.104`. One potential issue with this approach is that network diagrams are not always accurate. One way to verify accuracy is to search for DNS requests associated with `172.16.6.104`. **Sysmon Event ID 22 logs DNS requests** and can be used to determine the hostname. 

The following Splunk query shows DNS requests associated with the IP address:

```
index=windows EventCode=22 172.16.6.104
```

The logs show that DNS requests were made for `acc-win10-4` and the DNS result was `172.16.6.104`. Therefore, the network diagram mapping is accurate.
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

Additionally, searching for Sysmon Event ID 11 associated with this path and file reveals that the executable was created by the same PowerShell process with PID `5156`:

```
index=windows EventCode=11 TargetFilename="C:\\Users\\roxanne.farley\\AppData\\Local\\Microsoft\\Outlook\\OutlookSharing.exe"
```

The name of the malicious executable (`OutlookSharing.exe`) can be used to investigate the infected host and find running processes that communicated with the external IP address. With the external IP address and the hostname, the process tree can be systematically investigated to get to the executable downloaded by Gh0st RAT.

NEST: [[Question 3]]
