package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
)

type ErrorMessage struct {
	Error string `json:"error"`
}

const (
	KaspeskyType = "KasperskyType"
	TPLinkType   = "TPLinkType"
	DLinkType    = "DLinkType"
)

type LogFileKaspersky struct {
	FirewallType string `json:"firewallType"`
	ID           string `json:"id"`
	Date         string `json:"date"`
	Time         string `json:"time"`
	Description  string `json:"description"`
	ProtectType  string `json:"protectType"`
	Application  string `json:"application"`
	Result       string `json:"result"`
	ObjectAttack string `json:"objectAttack"`
	Port         string `json:"port"`
	Protocol     string `json:"protocol"`
	IPAddress    string `json:"ipAddress"`
}

type LogFileTPLink struct {
	FirewallType      string `json:"firewallType"`
	ID                string `json:"id"`
	Date              string `json:"date"`
	Time              string `json:"time"`
	TypeEvent         string `json:"typeEvent"`
	LevelSignificance string `json:"levelSignificance"`
	LogContent        string `json:"logContent"`
	MACAddress        string `json:"macAddress"`
	IPAddress         string `json:"ipAddress"`
	Protocol          string `json:"protocol"`
}

type LogFileDLink struct {
	FirewallType string `json:"firewallType"`
	ID           string `json:"id"`
	Date         string `json:"date"`
	Time         string `json:"time"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	CategoryID   string `json:"categoryID"`
	Rule         string `json:"rule"`
	Protocol     string `json:"proto"`
	SrcIf        string `json:"srcIf"`
	DstIf        string `json:"dstIf"`
	SrcIP        string `json:"srcIP"`
	DstIP        string `json:"dstIP"`
	SrcPort      string `json:"srcPort"`
	DstPort      string `json:"dstPort"`
	Event        string `json:"event"`
	Action       string `json:"action"`
}

var logfilesKaspersky []LogFileKaspersky
var logfilesTPLink []LogFileTPLink
var logfilesDLink []LogFileDLink
var protocolsName = []string{
	"TCP", "DHCP", "PPTP", "L2TP",
	"IPSEC", "FTP", "TFTP", "H323",
	"RTSP", "SSH", "UDP", "RTPS",
	"SSH", "SMB", "Telnet", "HTTP",
	"HTTPs", "HTTPS", "MTP", "SSL",
	"IMAP", "POP", "TSL"}

//*******************************************
// MARK: Parse log line
//*******************************************
func parseKasperskyString(line string) LogFileKaspersky {
	var lineSplit = strings.Split(line, "\t")
	var dateSplit = strings.Split(lineSplit[0], " ")

	var date = dateSplit[0]
	var time = dateSplit[1]
	var description = lineSplit[1]
	var protectType = lineSplit[2]
	var application = lineSplit[3]
	var result = lineSplit[4]
	var objectAttack = lineSplit[5]
	var ipAddress = findIP(objectAttack)
	var port = findPortInKaspersky(objectAttack)
	var protocol = findProtocol(objectAttack)

	// fmt.Println(protocol)

	return LogFileKaspersky{ID: "1", FirewallType: "Kaspersky", Date: date, Time: time, Description: description, ProtectType: protectType, Application: application, Result: result, ObjectAttack: objectAttack, IPAddress: ipAddress, Port: port, Protocol: protocol}
}

func parseTPLinkString(line string) LogFileTPLink {
	var lineSplit = strings.Split(line, "\t")
	var date = lineSplit[0]
	var time = lineSplit[0]
	var typeEvent = strings.TrimSpace(lineSplit[1])
	var levelSignificance = strings.TrimSpace(lineSplit[2])
	var logContent = lineSplit[3]

	var ipAddress = findIP(logContent)
	var macAddress = findMAC(logContent)
	var protocol = ""

	if typeEvent == "DHCP" {
		protocol = "DHCP"
	} else {
		protocol = findProtocol(logContent)
	}

	return LogFileTPLink{ID: "1", FirewallType: "TPLink", Date: date, Time: time, TypeEvent: typeEvent, LevelSignificance: levelSignificance, LogContent: logContent, IPAddress: ipAddress, MACAddress: macAddress, Protocol: protocol}
}

func parseDLinkString(line string) LogFileDLink {
	var lineSplit = strings.Split(line, " ")
	var date = lineSplit[0]
	var time = lineSplit[1]
	var category = lineSplit[2]
	var categoryID = lineSplit[3]
	var severity = lineSplit[4]
	var event = regexp.MustCompile(`event=\S*`).FindString(line)
	var action = regexp.MustCompile(`action=\S*`).FindString(line)
	var rule = regexp.MustCompile(`rule=\S*`).FindString(line)
	var proto = regexp.MustCompile(`connipproto=\S*`).FindString(line)

	return LogFileDLink{ID: "1", FirewallType: "DLink", Date: date, Time: time, Category: category, CategoryID: categoryID, Severity: severity, Event: event, Action: action, Rule: rule, Protocol: proto}
}

func findIP(input string) string {
	numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock

	regEx := regexp.MustCompile(regexPattern)
	return regEx.FindString(input)
}

func findMAC(input string) string {
	regexPattern := "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"

	regEx := regexp.MustCompile(regexPattern)
	return regEx.FindString(input)
}

func findPortInKaspersky(input string) string {
	regexPattern := "порт [0-9]+"

	regEx := regexp.MustCompile(regexPattern)
	var findString = regEx.FindString(input)
	var splitString = strings.Split(findString, " ")

	if len(splitString) == 2 {
		return splitString[1]
	}

	return findString
}

func findProtocol(input string) string {
	// regexPattern := `(?i)TCP\b|(?i)DHCP|(?i)DHCP|(?i)IPSEC`
	regexPattern := ``
	for _, element := range protocolsName {
		regexPattern += (`(?i)` + element + `\b|`)
	}

	regEx := regexp.MustCompile(regexPattern)
	var findString = regEx.FindString(input)

	return findString
}

//*******************************************
// MARK: Read log files and append to model
//*******************************************
func readKasperskyLogFile(path string) {
	file, err := os.Open(path)

	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	for _, eachline := range txtlines {
		logfilesKaspersky = append(logfilesKaspersky, parseKasperskyString(eachline))
	}
}

func readTPLinkLogFile(path string) {
	file, err := os.Open(path)

	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	for _, eachline := range txtlines {
		logfilesTPLink = append(logfilesTPLink, parseTPLinkString(eachline))
	}
}

func readDLinkLogFile(path string) {
	file, err := os.Open(path)

	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	for _, eachline := range txtlines {
		logfilesDLink = append(logfilesDLink, parseDLinkString(eachline))
	}
}

//*******************************************
// MARK: Load log files and read
//*******************************************
func loadLogFiles() {
	loadKasperskyLogs()
	loadTPLinkLogs()
	loadDLinkLogs()
}

func loadKasperskyLogs() {
	files, err := ioutil.ReadDir("./logfiles/kaspersky")

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		readKasperskyLogFile("./logfiles/kaspersky/" + f.Name())
	}
}

func loadTPLinkLogs() {
	files, err := ioutil.ReadDir("./logfiles/tplink")

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		readTPLinkLogFile("./logfiles/tplink/" + f.Name())
	}
}

func loadDLinkLogs() {
	files, err := ioutil.ReadDir("./logfiles/dlink")

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		readDLinkLogFile("./logfiles/dlink/" + f.Name())
	}
}

//*******************************************
// MARK: Update logs (ROUTES)
//*******************************************
func updateLogFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadLogFiles()
	json.NewEncoder(w).Encode(nil)
}

func updateLogFilesKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadKasperskyLogs()
	json.NewEncoder(w).Encode(nil)
}

func updateLogFilesTPLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadTPLinkLogs()
	json.NewEncoder(w).Encode(nil)
}

func updateLogFilesDLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadDLinkLogs()
	json.NewEncoder(w).Encode(nil)
}

//*******************************************
// MARK: Get log files (ROUTES)
//*******************************************
func getLogFilesKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

func getLogFilesTPLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesTPLink)
}

func getLogFilesDLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesDLink)
}

//*******************************************
// MARK: Get one log file by id (ROUTES)
//*******************************************
func getLogFileKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for _, item := range logfilesKaspersky {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	var error = ErrorMessage{Error: "Not found"}
	json.NewEncoder(w).Encode(error)
}

func getLogFileTPLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for _, item := range logfilesTPLink {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	var error = ErrorMessage{Error: "Not found"}
	json.NewEncoder(w).Encode(error)
}

func getLogFileDLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for _, item := range logfilesDLink {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	var error = ErrorMessage{Error: "Not found"}
	json.NewEncoder(w).Encode(error)
}

func main() {
	r := mux.NewRouter()

	loadLogFiles()

	r.HandleFunc("/api/logfiles/kaspersky", getLogFilesKaspersky).Methods("GET")
	r.HandleFunc("/api/logfiles/tplink", getLogFilesTPLink).Methods("GET")
	r.HandleFunc("/api/logfiles/dlink", getLogFilesDLink).Methods("GET")

	r.HandleFunc("/api/logfiles/kaspersky/{id}", getLogFileKaspersky).Methods("GET")
	r.HandleFunc("/api/logfiles/tplink/{id}", getLogFileTPLink).Methods("GET")
	r.HandleFunc("/api/logfiles/dlink/{id}", getLogFileDLink).Methods("GET")

	r.HandleFunc("/api/logfiles/update", updateLogFiles).Methods("GET")
	r.HandleFunc("/api/logfiles/kaspersky/update", updateLogFiles).Methods("GET")
	r.HandleFunc("/api/logfiles/tplink/update", updateLogFiles).Methods("GET")
	r.HandleFunc("/api/logfiles/dlink/update", updateLogFiles).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}
