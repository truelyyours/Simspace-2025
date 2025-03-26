**Select the technique that was used to compromise ez-www.**

Identify the process that communicated with the malicious IP address and investigate how the process was started on the domain controller.
## Background

`ez-www` was identified as a host communicating with `66.42.98.220`. Use the same methodology as for the `ez-dc` investigation to determine what technique was used to compromise `ez-www`.
## Solution
The following Splunk query performs a string search for `chrome_sync.exe` across all available process creation logs:

```
index=windows EventCode=1 chrome_sync.exe
```

The query returns a log generated this time by `ez-dc` running the following command: 

```
wmic /NODE:172.16.2.5 process call create "C:\program files\google\chrome\application\chrome_sync.exe"
```

## Analyst Insight

Windows Management Instrumentation command-line (`wmic.exe`) is a native Windows utility used to communicate with WMI. WMI is another Microsoft feature commonly abused by attackers for remote code execution and persistence.

NEXT: [[Question 8]]
