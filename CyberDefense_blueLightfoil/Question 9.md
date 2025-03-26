**Enter the name of the malicious payload that was used to compromise ez-file host.**

# Determining the Technique

The following query identifies the running process that is communicating with the malicious domain:

```
index=windows host=ez-file EventCode=22 66.42.98.220
```

The query reveals that the communication is initiated by `c:\windows\system32\rundll32.exe` with a PID of `1476`. `Rundll32.exe` is a native Windows executable that is used by many legitimate programs, but it can also be used by attackers to load and run malicious dynamic link library (DLL) files.

The following query shows the command line arguments associated with the process `rundll32.exe` with PID `1476`:

```
index=windows host=ez-file EventCode=1 Image="C:\\Windows\\system32\\rundll32.exe" ProcessId=1476
```

The query reveals the command associated with the running `rundll32.exe` process. The syntax shows `rundll32.exe` being used to load and execute the attackers malicious dll named `sliver.dll`.

The command line syntax is displayed below:

```
C:\Windows\system32\rundll32.exe C:\Windows\system32\sliver.dll,Start
```

## Analyst Insight

Use of `rundll32.exe` to execute malicious DLLs is a common technique used by attackers.

NEXT: [[Question 10]]
