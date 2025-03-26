**Select the six internal devices that communicated with the malicious domain or IP address.**

This phase of the investigation requires a combination of host and network logs.
## Background
Attackers rarely stay on a single computer after initial compromise. After they persist their initial access and escalate privileges they usually move laterally to other devices in the network in order to perform their desired actions on objective.

Another phase of this investigation is to identify the IP address or domain name that the malware is communicating with, and then to identify other devices in the network that are communicating with that IP or domain.

The malicious executable and the hostname that were identified earlier continue to help provide the path of this compromise.

Find the IP address and domain name with which `OutlookSharing.exe` on `acc-win10-4` is communicating. Use this information to find other devices in the network that are communicating with the malicious IP/Domain. Be aware that not all devices generate Sysmon logs, and Sysmon does not always generate a network connection log for every executable.

# Identifying Other Compromised Hosts

Sysmon Event ID 22 logs DNS requests of processes running on systems. Searching for external domains in DNS queries initiated by `OutlookSharing.exe` on `acc-win10-4` can identify the external domain name and IP address in one step. 

The following Splunk query identifies DNS requests associated with `OutlookSharing.exe` on `acc-win10-4`:

```
index=windows EventCode=22 host=acc-win10-4 OutlookSharing.exe
```

The query reveals that `OutlookSharing.exe` communicated with `www.dylerays.tk` with an IP address of `66.42.98.220`. The same IP/domain hosted the malicious file `OutlookSharing.exe`, originally named `RURAL_HEAT.exe`.

The following Splunk query returns Zeek connection logs for every host that communicated with `66.42.98.220`:

```
index=zeek sourcetype=zeek_conn id.resp_h=66.42.98.220
```

The following Splunk query implements stack counting to provide more readable output by providing only the IP addresses of devices that communicated with `66.42.98.220`:

```
index=zeek sourcetype=zeek_conn id.resp_h=66.42.98.220 | stats count by id.orig_h
```

The query returns the following list of IP addresses that communicated with `66.42.98.220`:

`172.16.2.3`

`172.16.2.5`

`172.16.2.6`

`172.16.2.7`

`172.16.5.71`

`172.16.6.104`

Hostnames of the IP addresses can be identified using the network diagram or by querying DNS records as was done previously.

`172.16.2.3 - ez-file` 

`172.16.2.5 - ez-www`

`172.16.2.6 - ez-proxy`

`172.16.2.7 - ez-dc`

`172.16.5.71 - dev-win10-1`

`172.16.6.104 - acc-win10-4`

Observe that `ez-proxy` is one of the identified hosts. This does not necessarily mean that `ez-proxy` was compromised. Instead, it likely represents traffic from infected hosts that were routed through the proxy. 

Processes on the newly identified hosts that communicated with `66.42.98.220` should be investigated.

## What I did

Figured that any zeek/dns resolvinng queryes will be in index=zeek so 
```
index=zeek dylerays
```

Then check the `id.orig_h` and get the IP addresses of who all requested for DNS resolution of the attacker's domain

NEXT: [[Question 6]]
