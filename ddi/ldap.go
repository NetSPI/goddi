/*
Package goddi contains ldap query functions
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
*/
package goddi

import (
	"fmt"
	"log"

	"gopkg.in/ldap.v2"
)

// GetUsers all domain users and checks for sensitive data in Description
// Reference: Scott Sutherland (@_nullbind)
func GetUsers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"memberOf"}
	keywords := []string{
		"cred",
		"pass",
		"pw",
		"spring",
		"summer",
		"fall",
		"winter"}
	filter := "(&(objectCategory=person)(objectClass=user)(SamAccountName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)
	warning := [][]string{}
	warning = append(warning, attributes)
	boolwarn := false

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Users: %d found\n", len(sr.Entries))

	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		samtype := entry.GetAttributeValue("sAMAccountType")
		upn := entry.GetAttributeValue("userPrincipalName")
		disname := entry.GetAttributeValue("displayName")
		given := entry.GetAttributeValue("givenName")
		desc := entry.GetAttributeValue("description")
		adm := entry.GetAttributeValue("adminCount")
		homedir := entry.GetAttributeValue("homeDirectory")
		mem := entry.GetAttributeValue("memberOf")
		data := []string{
			sam,
			samtype,
			upn,
			disname,
			given,
			desc,
			adm,
			homedir,
			mem}

		csv = append(csv, data)

		for _, keyword := range keywords {
			if caseInsensitiveContains(desc, keyword) {
				fmt.Printf("\t[*] Warning: keyword '%s' found!\n", keyword)
				boolwarn = true
				warning = append(warning, data)
			}
		}
	}

	writeCSV("Domain_Users", csv)

	if boolwarn {
		writeCSV("POTENTIAL_SENSITIVE_DATA_FOUND", warning)
	}
}

// GetUsersLocked locked out users
// Reference: Scott Sutherland (@_nullbind)
func GetUsersLocked(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"memberOf"}
	filter := "(&(sAMAccountType=805306368)(lockoutTime>=1))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Locked Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("sAMAccountType"),
			entry.GetAttributeValue("userPrincipalName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("givenName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("homeDirectory"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Users_Locked", csv)
}

// GetUsersDisabled disabled users
// Reference: Scott Sutherland (@_nullbind)
func GetUsersDisabled(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"memberOf"}
	filter := "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Disabled Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("sAMAccountType"),
			entry.GetAttributeValue("userPrincipalName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("givenName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("homeDirectory"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Users_Disabled", csv)
}

// GetUsersDeligation domain delegation
// Reference: Scott Sutherland (@_nullbind)
func GetUsersDeligation(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"description",
		"whenCreated",
		"whenChanged",
		"msDS-AllowedToDelegateTo"}
	filter := "(&(samAccountType=805306368)(|(UserAccountControl:1.2.840.113556.1.4.803:=524288)(UserAccountControl:1.2.840.113556.1.4.803:=16777216)))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Deligated Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("msDS-AllowedToDelegateTo")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Users_Deligation", csv)
}

// GetUsersNoExpire users with passwords not set to expire
// Reference: Scott Sutherland (@_nullbind)
func GetUsersNoExpire(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"displayName",
		"description",
		"whenCreated",
		"whenChanged"}
	filter := "(&(samAccountType=805306368)(|(UserAccountControl:1.2.840.113556.1.4.803:=65536)(msDS-UserDontExpirePassword=TRUE)))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Users with passwords not set to expire: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Users_NoExpirePasswords", csv)
}

// GetMachineAccountOldPassword machine accounts with password older than 45 days
// Reference: Scott Sutherland (@_nullbind)
func GetMachineAccountOldPassword(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemServicePack",
		"description",
		"memberOf",
		"adminCount"}
	fortyfive := getWinFiletime(45)
	filter := "(&(sAMAccountType=805306369)(pwdlastset<=" + fortyfive + "))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Machine Accounts with passwords older than 45 days: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("dNSHostName"),
			entry.GetAttributeValue("operatingSystem"),
			entry.GetAttributeValue("operatingSystemServicePack"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("memberOf"),
			entry.GetAttributeValue("adminCount")}
		csv = append(csv, data)
	}
	writeCSV("Domain_MachineAccount_Old_Password", csv)
}

// GetFSMORoles domain FSMO Roles
// Reference: Scott Sutherland (@_nullbind)
func GetFSMORoles(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"distinguishedname",
		"fSMORoleOwner"}
	filter := "(&(objectClass=*)(fSMORoleOwner=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] FSMO Roles: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.DN,
			entry.GetAttributeValue("fSMORoleOwner")}
		csv = append(csv, data)
	}
	writeCSV("Domain_FSMO_Roles", csv)
}

// GetDomainSite domain sites
// Reference: Scott Sutherland (@_nullbind)
func GetDomainSite(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"name",
		"distinguishedname",
		"whenCreated",
		"whenChanged"}
	baseDN = "CN=Sites,CN=Configuration," + baseDN
	filter := "(&(objectCategory=site)(name=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Sites: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("Name"),
			entry.DN,
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Sites", csv)
}

// GetDomainSubnet domain subnets
// Reference: Scott Sutherland (@_nullbind)
func GetDomainSubnet(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"site",
		"name",
		"description",
		"whenCreated",
		"whenChanged",
		"distinguishedname"}
	baseDN = "CN=Subnets,CN=Sites,CN=Configuration," + baseDN
	filter := "(objectCategory=subnet)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Subnets: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("site"),
			entry.GetAttributeValue("name"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.DN}
		csv = append(csv, data)
	}
	writeCSV("Domain_Subnets", csv)
}

// GetDomainAccountPolicy domain Account Policy
// Reference: Scott Sutherland (@_nullbind)
func GetDomainAccountPolicy(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"minPwdLength",
		"minPwdAge",
		"maxPwdAge",
		"pwdHistoryLength",
		"lockoutThreshold",
		"lockoutDuration",
		"lockOutObservationWindow",
		"pwdProperties",
		"whenChanged",
		"gPLink"}
	filter := "(objectClass=domainDNS)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Account Policy found\n")
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("minPwdLength"),
			convertPwdAge(entry.GetAttributeValue("minPwdAge")),
			convertPwdAge(entry.GetAttributeValue("maxPwdAge")),
			entry.GetAttributeValue("pwdHistoryLength"),
			entry.GetAttributeValue("lockoutThreshold"),
			convertLockout(entry.GetAttributeValue("lockoutDuration")),
			convertLockout(entry.GetAttributeValue("lockOutObservationWindow")),
			entry.GetAttributeValue("pwdProperties"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("gPLink")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Account_Policy", csv)
}

// GetDomainOUs domain OUs
// Reference: Scott Sutherland (@_nullbind)
func GetDomainOUs(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"ou",
		"dn",
		"ADsPath",
		"objectClass",
		"whenCreated",
		"whenChanged",
		"instanceType"}
	filter := "(&(objectCategory=organizationalUnit)(ou=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain OUs: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("ou"),
			entry.DN,
			baseDN,
			entry.GetAttributeValue("objectClass"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("instanceType")}
		csv = append(csv, data)
	}
	writeCSV("Domain_OUs", csv)
}

// GetDomainGPOs domain GPOs
// Reference: Scott Sutherland (@_nullbind)
func GetDomainGPOs(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"displayName",
		"dn",
		"gPCFileSysPath",
		"gPCUserExtensionNames",
		"gPCMachineExtensionNames"}
	filter := "(&(objectClass=groupPolicyContainer))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain GPOs: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("displayName"),
			entry.DN,
			entry.GetAttributeValue("gPCFileSysPath"),
			entry.GetAttributeValue("gPCUserExtensionNames"),
			entry.GetAttributeValue("gPCMachineExtensionNames")}
		csv = append(csv, data)
	}
	writeCSV("Domain_GPOs", csv)
}

// GetGroupMembers all members of given group
// Reference: Scott Sutherland (@_nullbind)
func GetGroupMembers(conn *ldap.Conn, baseDN string, group string) {

	attributes := []string{
		"memberOf",
		"sAMAccountName",
		"displayName"}
	csv := [][]string{}
	csv = append(csv, attributes)

	groupDN := getGroupDN(conn, baseDN, group)
	if len(groupDN) == 0 {
		writeCSV("Domain_Users_"+group, csv)
	}
	filter := "(&(objectCategory=user)(memberOf=" + groupDN + "))"

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] %s: %d users found\n", group, len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			group,
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("displayName")}
		csv = append(csv, data)
	}

	writeCSV("Domain_Users_"+group, csv)
}

// getGroupDN group dn
// Reference: Scott Sutherland (@_nullbind)
func getGroupDN(conn *ldap.Conn, baseDN string, group string) string {

	attributes := []string{
		"memberOf",
		"sAMAccountName",
		"displayName"}
	filter := "(&(objectCategory=group)(samaccountname=" + group + "))"

	sr := ldapSearch(baseDN, filter, attributes, conn)

	if len(sr.Entries) != 0 {
		groupDN := sr.Entries[0].DN
		return groupDN
	}
	groupDN := ""
	return groupDN
}

// GetDomainComputers all domain computers
// Reference: Scott Sutherland (@_nullbind)
func GetDomainComputers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemServicePack",
		"description"}
	filter := "(&(objectCategory=Computer)(SamAccountName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Computers: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("dNSHostName"),
			entry.GetAttributeValue("operatingSystem"),
			entry.GetAttributeValue("operatingSystemServicePack"),
			entry.GetAttributeValue("description")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Computers_All", csv)
}

// GetDomainControllers all domain controllers
// Reference: Scott Sutherland (@_nullbind)
func GetDomainControllers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemServicePack",
		"description"}
	filter := "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Controllers: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("dNSHostName"),
			entry.GetAttributeValue("operatingSystem"),
			entry.GetAttributeValue("operatingSystemServicePack"),
			entry.GetAttributeValue("description")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Controllers", csv)
}

// GetSPNs all SPNs and check for DA
// Reference: Scott Sutherland (@_nullbind)
func GetSPNs(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"servicePrincipalName",
		"dNSHostName",
		"memberOf"}
	filter := "(&(servicePrincipalName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)
	count := 0

	sr := ldapSearch(baseDN, filter, attributes, conn)

	for _, entry := range sr.Entries {
		da := ""
		if caseInsensitiveContains(entry.GetAttributeValue("memberOf"), "Domain Admins") {
			da = "Domain Admins"
		}

		spns := entry.GetAttributeValues("servicePrincipalName")
		count += len(spns)
		for _, spn := range spns {
			data := []string{
				entry.GetAttributeValue("sAMAccountName"),
				spn,
				entry.GetAttributeValue("dNSHostName"),
				da}
			csv = append(csv, data)
		}
	}
	fmt.Printf("[i] SPNs: %d found\n", count)
	writeCSV("Domain_SPNs", csv)
}

// GetLAPS LAPs passwords
// Reference: Scott Sutherland (@_nullbind), Karl Fosaaen (@kfosaaen), @_RastaMouse
// https://blog.netspi.com/running-laps-around-clearcleartext-passwords/
// https://rastamouse.me/2018/03/laps---part-2/
func GetLAPS(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"dNSHostName",
		"ms-MCS-AdmPwd",
		"ms-mcs-AdmPwdExpirationTime"}
	filter := "(&(objectCategory=Computer))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	for _, entry := range sr.Entries {
		if len(entry.GetAttributeValue("ms-MCS-AdmPwd")) > 0 {
			data := []string{
				entry.GetAttributeValue("dNSHostName"),
				entry.GetAttributeValue("ms-MCS-AdmPwd"),
				entry.GetAttributeValue("ms-mcs-AdmPwdExpirationTime")}
			csv = append(csv, data)
		}
	}
	fmt.Printf("[i] LAPS passwords: %d found\n", len(csv)-1)
	writeCSV("Domain_Passwords_LAPS", csv)
}

// GetDomainTrusts all domain trusts and details
// Reference: Scott Sutherland (@_nullbind)
func GetDomainTrusts(conn *ldap.Conn, baseDN string) {
	attributes := []string{
		"sourcedomain",
		"trustPartner",
		"dn",
		"trustType",
		"trustDirection",
		"trustAttributes",
		"whenCreated",
		"whenChanged",
		"objectClass"}
	filter := "(objectClass=trustedDomain)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Trusts: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var ttype, directory, attribute string
		switch trust := entry.GetAttributeValue("trustType"); trust {
		case "1":
			ttype = "Downlevel Trust (Windows NT domain external)"
		case "2":
			ttype = "Uplevel Trust (Active Directory domain - parent-child, root domain, shortcut, external, or forest)"
		case "3":
			ttype = "MIT (non-Windows Kerberos version 5 realm)"
		case "4":
			ttype = "DCE (Theoretical trust type - DCE refers to Open Group's Distributed Computing)"
		}
		switch dir := entry.GetAttributeValue("trustDirection"); dir {
		case "0":
			directory = "Disabled"
		case "1":
			directory = "Inbound"
		case "2":
			directory = "Outbound"
		case "3":
			directory = "Bidirectional"
		}
		switch attrib := entry.GetAttributeValue("trustAttributes"); attrib {
		case "1":
			attribute = "non_transitive"
		case "2":
			attribute = "uplevel_only"
		case "4":
			attribute = "quarantined_domain"
		case "8":
			attribute = "forest_transitive"
		case "10":
			attribute = "cross_organization"
		case "20":
			attribute = "within_forest"
		case "40":
			attribute = "treat_as_external"
		case "80":
			attribute = "trust_uses_rc4_encryption"
		case "100":
			attribute = "trust_uses_aes_keys"
		default:
			attribute = entry.GetAttributeValue("trustAttributes")
		}
		data := []string{
			baseDN,
			entry.GetAttributeValue("trustPartner"),
			entry.DN,
			ttype,
			directory,
			attribute,
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("objectClass")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Trusts", csv)
}

// GetGroupsAll all groups
// Reference: Scott Sutherland (@_nullbind)
func GetGroupsAll(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dn",
		"description",
		"adminCount",
		"member"}
	filter := "(&(objectClass=group)(samaccountname=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Groups: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.DN,
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("member")}
		csv = append(csv, data)
	}

	writeCSV("Domain_Groups_All", csv)
}

// Helper function for LDAP search
func ldapSearch(searchDN string, filter string, attributes []string, conn *ldap.Conn) *ldap.SearchResult {

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := conn.SearchWithPaging(searchRequest, 200)
	if err != nil {
		log.Fatal(err)
	}

	return sr

}
