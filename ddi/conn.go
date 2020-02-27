// Functions to handle ldap connections and bind

package goddi

import (
	"crypto/tls"
	"fmt"
	"log"

	"gopkg.in/ldap.v2"
)

// LdapInfo contains connection info
type LdapInfo struct {
	LdapServer       string
	LdapIP           string
	LdapPort         uint16
	LdapTLSPort      uint16
	User             string
	Usergpp          string
	Pass             string
	Domain           string
	Conn             *ldap.Conn
	Unsafe           bool
	StartTLS         bool
	ForceInsecureTLS bool
	MntPoint         string
}

func dial(li *LdapInfo) {

	if li.Unsafe {

		fmt.Printf("[i] Begin PLAINTEXT LDAP connection to '%s' (%s)...\n", li.LdapServer, li.LdapIP)
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapPort))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[i] PLAINTEXT LDAP connection to '%s' (%s) successful...\n", li.LdapServer, li.LdapIP)
		li.Conn = conn

	} else if li.StartTLS {

		fmt.Printf("[i] Begin PLAINTEXT LDAP connection to '%s' (%s)...\n", li.LdapServer, li.LdapIP)
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapPort))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[i] PLAINTEXT LDAP connection to '%s' (%s) successful...\n[i] Upgrade to StartTLS connection...\n", li.LdapServer, li.LdapIP)

		err = conn.StartTLS(&tls.Config{ServerName: li.LdapServer, InsecureSkipVerify: li.ForceInsecureTLS})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[i] Upgrade to StartTLS connection successful...\n")
		li.Conn = conn

	} else {

		fmt.Printf("[i] Begin LDAP TLS connection to '%s' (%s)...\n", li.LdapServer, li.LdapIP)
		config := &tls.Config{ServerName: li.LdapServer, InsecureSkipVerify: li.ForceInsecureTLS}
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapTLSPort), config)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[i] LDAP TLS connection to '%s' (%s) successful...\n", li.LdapServer, li.LdapIP)
		li.Conn = conn
	}
}

// Connect authenticated bind to ldap connection
func Connect(li *LdapInfo) {

	dial(li)
	fmt.Printf("[i] Begin BIND...\n")
	err := li.Conn.Bind(li.User, li.Pass)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[i] BIND with '%s' successful...\n[i] Begin dump domain info...\n", li.User)
}
