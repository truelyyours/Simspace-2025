**Select the technique that was used to compromise ez-dc.**

Identify the process that communicated with the malicious IP address and investigate how the process was started on the domain controller.
## Background

`ez-dc` was identified as a host communicating with `66.42.98.220`. In order to determine the technique used to compromise `ez-dc`, identify the process that communicated with the malicious IP address and investigate how the process was started on the domain controller. 

Sysmon network connection logs are often one of the first places that an analyst looks when investigating connections created by processes. However, Sysmon uses include and exclude rules to determine if connections made by certain processes are logged. This means that if an executable is located in a directory that is part of the exclude list for network connections, then connections made by that executable are not logged. In cases where these network connection logs are not captured, it can be useful to query other logs such as Sysmon DNS logs Event ID 22.

# Determining the Technique

Sysmon network connection event logs were not created for the executable communicating with `66.42.98.220`. Therefore, the following Splunk query returns logs of DNS requests made on ez-dc that contain the IP `66.42.98.220`:

```
index=windows host=ez-dc EventCode=22 66.42.98.220
```

The query shows two processes that made DNS queries for `www.dylerays.tk`, which is the domain name associated with `66.42.98.220`. Since the goal was to determine how `ez-dc` was compromised, the focus should be on **the earliest DNS log associated with this domain**. The executable associated with the first DNS request is `C:\Windows\System32\bcdupdate.exe`.

One way to identify how `bcdupdate.exe` was executed on `ez-dc` is to search for *process creation events* on all hosts that contain the string `bcdupdate.exe`. 

The following Splunk query performs a string search for `bcdupdate.exe` across all available process creation logs: 

```
index=windows EventCode=1 bcdupdate.exe
```

This query returns two log entries. The earliest log was generated by the host `acc-win10-4` and shows that the following command was run by the previously identified malicious `outlooksharing.exe` process:

```
schtasks.exe /change /s ez-dc /u charley.fritz /p W9H$Rg5D#B7@ /TN \MIcrosoft\Windows\Chkdsk\SyspartUpdate /TR C:\Windows\system32\bcdupdate.exe /RU SYSTEM
```

Scheduled tasks (`schtasks.exe`) is a native Windows utility that can be used to manage scheduled tasks on local and remote computers. This is a common technique used by attackers to gain remote code execution as well as achieve persistence.

## Analyst Insight

Be aware that the command `schtasks` contains the username `charley.fritz` and what appears to be a clear text password. It is possible that the attacker was able to find credentials for this user somewhere in the environment and then abuse those credentials during their attack.

NEXT: [[Question 7]]
