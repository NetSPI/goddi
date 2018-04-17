# goddi - Go dump domain info
[![licence badge]][licence]
[![Go Report Card](https://goreportcard.com/badge/github.com/NetSPI/goddi)](https://goreportcard.com/report/github.com/NetSPI/goddi)

[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg?style=flat-square
[licence]:https://github.com/NetSPI/goddi/blob/master/LICENSE

Based on work from Scott Sutherland (@_nullbind), Antti Rantasaari, Eric Gruber (@egru), Will Schroeder (@harmj0y), and the <a href="https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon">PowerView authors</a>.


## Install
Use the executables in the releases section. If you want to build it yourself, make sure that your go environment is setup according to the <a href="https://golang.org/doc/code.html">Go setup doc</a>. The goddi package also uses the below package.

	go get gopkg.in/ldap.v2

### Windows
Tested on Windows 10 and 8.1 (go1.10 windows/amd64).

### Linux
Tested on Kali Linux (go1.10 linux/amd64).

- umount, mount, and cifs-utils need to be installed for mapping a share for GetGPP
```
apt-get update
apt-get install -y mount cifs-utils
```
- make sure nothing is mounted at /mnt/goddi/
- make sure to run with `sudo`

## Run
When run, will default to using TLS (tls.Client method) over 636. On Linux, make sure to run with `sudo`.

- username: Target user. Required parameter.
- password: Target user's password. Required parameter.
- domain: Full domain name. Required parameter.
- dc: DC to target. Can be either an IP or full hostname. Required parameter.
- startTLS: Use to StartTLS over 389.
- unsafe: Use for a plaintext connection.

```
PS C:\Users\Administrator\Desktop> .\godditest-windows-amd64.exe -username=testuser -password="testpass!" -domain="test.local" -dc="dc.test.local" -unsafe
[i] Begin PLAINTEXT LDAP connection to 'dc.test.local'...
[i] PLAINTEXT LDAP connection to 'dc.test.local' successful...
[i] Begin BIND...
[i] BIND with 'testuser' successful...
[i] Begin dump domain info...
[i] Domain Trusts: 1 found
[i] Domain Controllers: 1 found
[i] Users: 12 found
        [*] Warning: keyword 'pass' found!
        [*] Warning: keyword 'fall' found!
[i] Domain Admins: 4 users found
[i] Enterprise Admins: 1 users found
[i] Forest Admins: 0 users found
[i] Locked Users: 0 found
[i] Disabled Users: 2 found
[i] Groups: 45 found
[i] Domain Sites: 1 found
[i] Domain Subnets: 0 found
[i] Domain Computers: 17 found
[i] Deligated Users: 0 found
[i] Users with passwords not set to expire: 6 found
[i] Machine Accounts with passwords older than 45 days: 18 found
[i] Domain OUs: 8 found
[i] Domain Account Policy found
[i] Domain GPOs: 7 found
[i] FSMO Roles: 3 found
[i] SPNs: 122 found
[i] LAPS passwords: 0 found
[i] GPP enumeration starting. This can take a bit...
[i] GPP passwords: 7 found
[i] CSVs written to 'csv' directory in C:\Users\Administrator\Desktop
[i] Execution took 1.4217256s...
[i] Exiting...
```

## Functionality
StartTLS and TLS (tls.Client func) connections supported. Connections over TLS are default. All output goes to CSVs and are created in /csv/ in the current working directory. Dumps:

- Domain users. Also searches Description for keywords and prints to a seperate csv ex. "Password" was found in the domain user description.
- Users in priveleged user groups (DA, EA, FA).
- Users with passwords not set to expire.
- User accounts that have been locked or disabled.
- Machine accounts with passwords older than 45 days.
- Domain Computers.
- Domain Controllers.
- Sites and Subnets.
- SPNs and includes csv flag if domain admin (a flag to note SPNs that are DAs in the SPN CSV output).
- Trusted domain relationships.
- Domain Groups.
- Domain OUs.
- Domain Account Policy.
- Domain deligation users.
- Domain GPOs.
- Domain FSMO roles.
- LAPS passwords.
- GPP passwords. On Windows, defaults to mapping Q. If used, will try another mapping until success R, S, etc... On Linux, /mnt/goddi is used.

## Roadmap
- Add support for running from current user context on Windows. Automatically get current domain and run in current user context.
- Add robust error handling for GetGPP (net use and mount)
- Improve XML parsing for GetGPP

## Known Issues
- Execution can fail at GetGPP if there are errors mapping a share or mounting /mnt/goddi. If goddi fails during GetGPP do the following checks.
	- Windows: check what shares are mounted with `net use`. If there is a share mounted to the target dc from goddi, remove it with `net use Q: /delete` where Q: is the problematic share.
	- Linux: check if /mnt/goddi exists. If something is mounted, use `umount /mnt/goddi`. Make sure goddi is run with sudo.

## References
- Scott Sutherland (@_nullbind)
- Antti Rantasaari
- Eric Gruber (@egru)
- Will Schroeder (@harmj0y)
- Karl Fosaaen (@kfosaaen)
- @_RastaMouse
- Chris Campbell (@obscuresec)
- Leon Teale (@LeonTeale)
