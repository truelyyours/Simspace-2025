## **Investigation Recap**

The investigation started with an indication of Gh0st RAT malware from an external source.

Suricata IDS logs were used to identify traffic with a matching Gh0stRAT signature revealing the internal host `acc-win10-4` communicating with an external IP of `119.28.139.120`. This information was used to identify the Gh0stRAT process named `svchost_console.exe` running on `acc-win10-4`.

Further investigation of activity associated with `svchost_console.exe` showed that the attacker used PowerShell to download a file named `RURAL_HEAT.exe` from `www.dylerays.tk`, save it locally as `outlooksharing.exe`, and then execute `outlooksharing.exe`.

Investigation of activity associated with `outlooksharing.exe` revealed that the attacker used a registry run key named `outlooksharing` to achieve user persistence on `acc-win10-4`. DNS logs were used to identify that `outlooksharing.exe` was communicating with `www.dylerays.tk/66.42.98.220`. 

Proxy logs were used to identify other hosts that were communicating with `66.42.98.220`. This revealed that hosts `ez-dc`, `ez-file`, `ez-www`, and `dev-win10-1` were also likely compromised. 

The malicious network connection on each host was investigated to determine the techniques used to compromise each host.

Finally, investigation of user creation and group membership logs revealed the creation of a backdoor administrator account named `eugene.belford`.