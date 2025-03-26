/*
Go dump domain info.
Author: Thomas Elling (@thomas_elling), NetSPI 2018
References: Based on work from Scott Sutherland (@_nullbind), Antti Rantasaari, Eric Gruber (@egru),
@harmj0y, and the PowerView authors https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon.

Requirements: gopkg.in/ldap.v2

Usage: goddi-windows-amd64.exe -username=testuser -password="testpass!" -domain="test.local" -dc="dc.test.local"
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	goddi "github.com/swarley7/goddi/ddi"
)

func main() {
	ldapServer := flag.String("dc", "", "Hostname of DC to connect to. ex. -dc=\"dc.test.local\"")
	ldapIP := flag.String("dc-ip", "", "Optional: IP address of DC to connect to (useful if proxying without DNS magic)")
	domain := flag.String("domain", "", "Domain, ex. -domain=\"test.local\"")
	user := flag.String("username", "", "Username to connect with, ex. -username=\"testuser@example.org\"")
	pass := flag.String("password", "", "Password to connect with, ex. -password=\"testpass!\"")
	startTLS := flag.Bool("startTLS", false, "Use StartTLS on 389. Default is TLS on 636")
	unsafe := flag.Bool("unsafe", false, "Use for testing with plaintext connection")
	forceInsecureTLS := flag.Bool("insecure", false, "Ignore TLS errors (e.g., self-signed certificates)")
	mntpoint := flag.String("mountpoint", "", "Mount point to use for gpp_password")
	basednArg := flag.String("basedn", "", "Base DN to use. If set, this overrides the domain-based calculation.")

	flag.Parse()


	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	if *mntpoint == "" {
		*mntpoint = dir + "/goddi_mount"
	}
	if !strings.HasSuffix(*mntpoint, "/") {
		*mntpoint = *mntpoint + "/"
	}

	if (len(*ldapServer) == 0 && len(*ldapIP) == 0) || len(*domain) == 0 || len(*user) == 0 || len(*pass) == 0 {
		flag.PrintDefaults()
		log.Fatal("[ERROR] Provide username, password, DC, and domain!\n")
	}
	if *ldapIP == "" {
		*ldapServer, *ldapIP = goddi.ValidateIPHostname(*ldapServer, *domain)
	} else {
		ldapServer = ldapIP
	}

	// If -basedn is set, we will use that. Otherwise, we require domain and derive baseDN.
	var baseDN string
	if *basednArg != "" {
		baseDN = *basednArg
	} else {
		if len(*domain) == 0 {
			flag.PrintDefaults()
			log.Fatal("[ERROR] Provide either a valid domain (-domain) or a custom baseDN (-basedn)!\n")
		}
		baseDN = "dc=" + strings.Replace(*domain, ".", ",dc=", -1)
	}

	username := *user

	li := &goddi.LdapInfo{
		LdapServer:       *ldapServer,
		LdapIP:           *ldapIP,
		LdapPort:         uint16(389),
		LdapTLSPort:      uint16(636),
		User:             username,
		Usergpp:          *user,
		Pass:             *pass,
		Domain:           *domain,
		Unsafe:           *unsafe,
		StartTLS:         *startTLS,
		ForceInsecureTLS: *forceInsecureTLS,
		MntPoint:         *mntpoint,
	}
	//fmt.Printf("[i] basedn: %s\n", baseDN)
	//fmt.Printf("[i] user: %s\n", username)


	goddi.Connect(li)
	defer li.Conn.Close()

	start := time.Now()
	goddi.GetDomainTrusts(li.Conn, baseDN)
	goddi.GetDomainControllers(li.Conn, baseDN)
	goddi.GetUsers(li.Conn, baseDN)
	goddi.GetGroupMembers(li.Conn, baseDN, "Domain Admins")
	goddi.GetGroupMembers(li.Conn, baseDN, "Enterprise Admins")
	goddi.GetGroupMembers(li.Conn, baseDN, "Forest Admins")
	goddi.GetUsersLocked(li.Conn, baseDN)
	goddi.GetUsersDisabled(li.Conn, baseDN)
	goddi.GetGroupsAll(li.Conn, baseDN)
	goddi.GetDomainSite(li.Conn, baseDN)
	goddi.GetDomainSubnet(li.Conn, baseDN)
	goddi.GetDomainComputers(li.Conn, baseDN)
	goddi.GetUsersDeligation(li.Conn, baseDN)
	goddi.GetUsersNoExpire(li.Conn, baseDN)
	goddi.GetMachineAccountOldPassword(li.Conn, baseDN)
	goddi.GetDomainOUs(li.Conn, baseDN)
	goddi.GetDomainAccountPolicy(li.Conn, baseDN)
	goddi.GetDomainGPOs(li.Conn, baseDN)
	goddi.GetFSMORoles(li.Conn, baseDN)
	goddi.GetSPNs(li.Conn, baseDN)
	goddi.GetLAPS(li.Conn, baseDN)
	goddi.GetGPP(li.Conn, li.Domain, li.LdapServer, li.Usergpp, li.Pass, li.MntPoint)
	stop := time.Since(start)

	cwd := goddi.GetCWD()
	fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s...\n[i] Exiting...\n", cwd, stop)
}