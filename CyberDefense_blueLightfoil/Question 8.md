**Select the technique that was used to compromise dev-win10-1.**

Identify the process that communicated with the malicious IP address `66.42.98.220` and investigate how the process was started on the domain controller.
## Background

Use the same methodology as for the `ez-dc` and `ez-www` investigations to determine what technique was used to compromise `dev-win10-1`.

# Determining the Technique

Sysmon network connections logs were not created for the executable that communicated with `66.42.98.220`. Therefore, the following Splunk query returns logs of DNS requests made on `dev-win10-1` that contain the IP `66.42.98.220`:

```
index=windows host=dev-win10-1 EventCode=22 66.42.98.220
```

The query reveals that `C:\Windows\System32\wisp.exe` made the DNS request for `www.dylerays.tk`.

The following Splunk query performs a string search for wisp.exe across all available process creation logs:

```
index=windows EventCode=1 wisp.exe
```

The query once again shows a log generated by `ez-dc` running the following command:

```
sc \\dev-win10-1 create WISP binPath= C:\Windows\system32\wisp.exe DisplayName= WISP error= ignore start= auto
```

`sc.exe` is a native Windows command line utility used for managing services on local and remote computers. Service manipulation is a very common technique used by attackers for remote code execution and persistence.

NEXT: [[Question 9]]
