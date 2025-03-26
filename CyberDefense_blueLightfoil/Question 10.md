**Enter the account name of the newly created domain administrator.**

Answer format: `firstname.lastname`
Search for evidence of new administrator accounts in the `ez.lan` domain.
## Background
It is common for attackers to create backdoor administrative accounts during an attack.

# Identify Unauthorized Account

One way to approach this question is to review event logs associated with new user creation.

The following Splunk query shows all account creation events:

```
index=windows EventCode=4720 | stats count by _time SAM_Account_Name
```

The query shows several instances of new users being created. Many of these accounts were created as decoys to provide cover for the malicious account. However, just because accounts were created does not mean that they are domain administrators. The best way to find new domain administrators is to find events associated with new group membership. 

The following Splunk query shows changes to user group assignments:

```
index=windows EventCode=4728
```

The query returns a single log that reveals the user `eugene.belford` was added to the group `Domain Admins`.

NEXT: [[DONE]]

