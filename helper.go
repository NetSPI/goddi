// Helper functions

package goddi

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// WINDOWS_EPOCH_FILETIME January 1, 1601 UTC (coordinate universal time)
const WINDOWS_EPOCH_FILETIME int64 = 116444736000000000

// Writing output to csv
// Reference: https://golangcode.com/write-data-to-a-csv-file/
func writeCSV(filename string, data [][]string) {

	cwd := GetCWD()
	csvdir := cwd + "/csv/"
	if _, err := os.Stat(csvdir); os.IsNotExist(err) {
		os.Mkdir(csvdir, os.ModePerm)
	}

	file, err := os.Create(csvdir + filename + ".csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, value := range data {
		err := writer.Write(value)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Get sub directories
func getSubDirs(drive string) []string {

	file, err := os.Open(drive)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	list, _ := file.Readdirnames(0)
	return list
}

// GetCWD returns executable's current directory
func GetCWD() string {

	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cwd := filepath.Dir(exe)
	return cwd
}

// Helper function to decrypt GPP cpassword
// References:
// https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
// https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
func decrypt(cpassword string) string {

	// 32 byte AES key
	// http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
	key := "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"

	// hex decode the key
	decoded, _ := hex.DecodeString(key)
	block, err := aes.NewCipher(decoded)
	if err != nil {
		log.Fatal(err)
	}

	// add padding to base64 cpassword if necessary
	m := len(cpassword) % 4
	if m != 0 {
		cpassword += strings.Repeat("=", 4-m)
	}

	// base64 decode cpassword
	decodedpassword, errs := base64.StdEncoding.DecodeString(cpassword)
	if errs != nil {
		log.Fatal(errs)
	}

	if len(decodedpassword) < aes.BlockSize {
		log.Fatal("Cpassword block size too short...\n")
	}

	var iv = []byte{00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00}

	if (len(decodedpassword) % aes.BlockSize) != 0 {
		log.Fatal("Blocksize must be multiple of decoded message length...\n")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decodedpassword, decodedpassword)

	// remove the padding at the end of password
	length := len(decodedpassword)
	unpadding := int(decodedpassword[length-1])
	clear := decodedpassword[:(length - unpadding)]

	return string(clear)
}

// Converts ldap password age
func convertPwdAge(pwdage string) string {

	f, _ := strconv.ParseFloat((strings.Replace(pwdage, "-", "", -1)), 64)
	age := ((f / (60 * 10000000)) / 60) / 24
	flr := math.Floor(age)
	s := strconv.Itoa(int(flr))

	return s
}

// Convers ldap lockout
func convertLockout(lockout string) string {

	i, _ := strconv.Atoi(strings.Replace(lockout, "-", "", -1))
	age := i / (60 * 10000000)
	s := strconv.Itoa(age)

	return s
}

// Returns current time minus number of days ago in Windows Filetime
// https://support.microsoft.com/en-us/help/167296/how-to-convert-a-unix-time-t-to-a-win32-filetime-or-systemtime
func getWinFiletime(numdays int) string {

	win := time.Now().UTC().UnixNano()
	win /= 100
	win += WINDOWS_EPOCH_FILETIME

	nanosago := 10000000 * 60 * 60 * 24 * int64(numdays)
	nanosago /= 100
	pasttime := win - nanosago

	str := strconv.FormatInt(pasttime, 10)
	return str
}

// https://stackoverflow.com/questions/24836044/case-insensitive-string-search-in-golang
func caseInsensitiveContains(s, substr string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}

// ValidateIPHostname parses and returns hostname and ip for dc
func ValidateIPHostname(ldapServer string, domain string) (string, string) {
	var ldapIP string
	if net.ParseIP(ldapServer) != nil {
		ldapIP = ldapServer
		hostnames, err := net.LookupAddr(ldapServer)
		if err != nil {
			log.Fatal(err)
		}
		for _, host := range hostnames {
			if caseInsensitiveContains(host, domain) {
				ldapServer = strings.Trim(host, ".")
			}
		}
	} else {
		addr, err := net.LookupIP(ldapServer)
		if err != nil {
			log.Fatal(err)
		}
		ldapIP = addr[0].String()
	}
	return ldapServer, ldapIP
}
