// Helper functions for GPP cpasswords

package goddi

import (
	"encoding/xml"
	"io/ioutil"
	"os"
)

// Groups groups.xml
type Groups struct {
	XMLName xml.Name `xml:"Groups"`
	Users   []User   `xml:"User"`
}

// User groups.xml
type User struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// Drives drives.xml
type Drives struct {
	XMLName xml.Name `xml:"Drives"`
	Drives  []Drive  `xml:"Drive"`
}

// Drive drive.xml
type Drive struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// DataSources datasources.xml
type DataSources struct {
	XMLName     xml.Name     `xml:"DataSources"`
	DataSources []DataSource `xml:"DataSource"`
}

// DataSource datasources.xml
type DataSource struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// NTServices services.xml
type NTServices struct {
	XMLName    xml.Name    `xml:"NTServices"`
	NTServices []NTService `xml:"NTService"`
}

// NTService services.xml
type NTService struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// Printers printers.xml
type Printers struct {
	XMLName  xml.Name        `xml:"Printers"`
	Printers []SharedPrinter `xml:"SharedPrinter"`
}

// SharedPrinter printers.xml
type SharedPrinter struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// ScheduledTasks scheduledtasks.xml
type ScheduledTasks struct {
	XMLName        xml.Name `xml:"ScheduledTasks"`
	ScheduledTasks []Task   `xml:"Task"`
}

// Task scheduledtasks.xml
type Task struct {
	Properties Properties `xml:"Properties"`
	Changed    string     `xml:"changed,attr"`
}

// Properties groups.xml, drives.xml, datasources.xml, services.xml, printers.xml, scheduledtasks.xml
type Properties struct {
	Runas       string `xml:"runAs,attr"`
	Accountname string `xml:"accountName,attr"`
	Username    string `xml:"userName,attr"`
	Cpassword   string `xml:"cpassword,attr"`
	Newname     string `xml:"newName,attr"`
}

// Helper function to parse XML files for cpassword
// Reference: https://msdn.microsoft.com/en-us/library/cc232650.aspx
func parseXML(fullpath string, csvptr *[][]string) {

	xmlFile, err := os.Open(fullpath)
	if err != nil {
		return
	}
	defer xmlFile.Close()

	if caseInsensitiveContains(fullpath, "Groups.xml") {
		var groups Groups
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &groups)

		for i := 0; i < len(groups.Users); i++ {
			if len(groups.Users[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				groups.Users[i].Properties.Username,
				groups.Users[i].Properties.Cpassword,
				decrypt(groups.Users[i].Properties.Cpassword),
				groups.Users[i].Changed,
				groups.Users[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	} else if caseInsensitiveContains(fullpath, "Drives.xml") {
		var drives Drives
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &drives)

		for i := 0; i < len(drives.Drives); i++ {
			if len(drives.Drives[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				drives.Drives[i].Properties.Username,
				drives.Drives[i].Properties.Cpassword,
				decrypt(drives.Drives[i].Properties.Cpassword),
				drives.Drives[i].Changed,
				drives.Drives[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	} else if caseInsensitiveContains(fullpath, "Datasources.xml") {
		var datasources DataSources
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &datasources)

		for i := 0; i < len(datasources.DataSources); i++ {
			if len(datasources.DataSources[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				datasources.DataSources[i].Properties.Username,
				datasources.DataSources[i].Properties.Cpassword,
				decrypt(datasources.DataSources[i].Properties.Cpassword),
				datasources.DataSources[i].Changed,
				datasources.DataSources[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	} else if caseInsensitiveContains(fullpath, "Services.xml") {
		var ntservices NTServices
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &ntservices)

		for i := 0; i < len(ntservices.NTServices); i++ {
			if len(ntservices.NTServices[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				ntservices.NTServices[i].Properties.Accountname,
				ntservices.NTServices[i].Properties.Cpassword,
				decrypt(ntservices.NTServices[i].Properties.Cpassword),
				ntservices.NTServices[i].Changed,
				ntservices.NTServices[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	} else if caseInsensitiveContains(fullpath, "Printers.xml") {
		var printers Printers
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &printers)

		for i := 0; i < len(printers.Printers); i++ {
			if len(printers.Printers[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				printers.Printers[i].Properties.Accountname,
				printers.Printers[i].Properties.Cpassword,
				decrypt(printers.Printers[i].Properties.Cpassword),
				printers.Printers[i].Changed,
				printers.Printers[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	} else if caseInsensitiveContains(fullpath, "Scheduledtasks.xml") {
		var scheduledtasks ScheduledTasks
		byteValue, _ := ioutil.ReadAll(xmlFile)
		xml.Unmarshal(byteValue, &scheduledtasks)

		for i := 0; i < len(scheduledtasks.ScheduledTasks); i++ {
			if len(scheduledtasks.ScheduledTasks[i].Properties.Cpassword) == 0 {
				continue
			}
			temp := []string{
				fullpath,
				scheduledtasks.ScheduledTasks[i].Properties.Runas,
				scheduledtasks.ScheduledTasks[i].Properties.Cpassword,
				decrypt(scheduledtasks.ScheduledTasks[i].Properties.Cpassword),
				scheduledtasks.ScheduledTasks[i].Changed,
				scheduledtasks.ScheduledTasks[i].Properties.Newname}
			*csvptr = append(*csvptr, temp)
		}
	}
}
