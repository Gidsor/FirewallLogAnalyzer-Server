package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
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
	ID           int    `json:"id"`
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
	ID                int    `json:"id"`
	Date              string `json:"date"`
	Time              string `json:"time"`
	TypeEvent         string `json:"typeEvent"`
	LevelSignificance string `json:"levelSignificance"`
	LogContent        string `json:"logContent"`
	MACAddress        string `json:"macAddress"`
	IPAddress         string `json:"ipAddress"`
	Protocol          string `json:"protocol"`
	Event             string `json:"event"`
}

type LogFileDLink struct {
	FirewallType    string `json:"firewallType"`
	ID              int    `json:"id"`
	Date            string `json:"date"`
	Time            string `json:"time"`
	Severity        string `json:"severity"`
	Category        string `json:"category"`
	CategoryID      string `json:"categoryID"`
	Rule            string `json:"rule"`
	Protocol        string `json:"proto"`
	SrcIf           string `json:"srcIf"`
	DstIf           string `json:"dstIf"`
	SrcIP           string `json:"srcIP"`
	DstIP           string `json:"dstIP"`
	SrcPort         string `json:"srcPort"`
	DstPort         string `json:"dstPort"`
	Event           string `json:"event"`
	Action          string `json:"action"`
	Conn            string `json:"conn"`
	ConnNewSrcIp    string `json:"connnewsrcip"`
	ConnNewSrcPort  string `json:"connnewsrcport"`
	ConnNewDestIp   string `json:"connnewdestip"`
	ConnNewDestPort string `json:"connnewdestport"`
	OrigSent        string `json:"origsent"`
	TermSent        string `json:"termsent"`
	ConnTime        string `json:"conntime"`
}

var idCounter = 0
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

	idCounter++

	return LogFileKaspersky{
		ID:           idCounter,
		FirewallType: "Kaspersky",
		Date:         date,
		Time:         time,
		Description:  description,
		ProtectType:  protectType,
		Application:  application,
		Result:       result,
		ObjectAttack: objectAttack,
		IPAddress:    ipAddress,
		Port:         port,
		Protocol:     protocol}
}

var dateTPLink = ""

func parseTPLinkString(line string) {
	if line == "" || strings.Contains(line, "#") {
		if strings.Contains(line, "Time = ") {
			var lineSplit = strings.Split(line, " ")
			dateTPLink = lineSplit[3]
		}
		return
	}
	var lineSplit = strings.Split(line, "\t")
	var date = strings.Split(lineSplit[0], " ")[0] + " " + strings.Split(lineSplit[0], " ")[1]
	if dateTPLink != "" {
		date = dateTPLink
	}
	var time = strings.Split(lineSplit[0], " ")[len(strings.Split(lineSplit[0], " "))-1]
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
	var event = strings.Replace(logContent, ipAddress, "", -1)
	event = strings.Replace(event, macAddress, "", -1)

	idCounter++

	var log = LogFileTPLink{
		ID:                idCounter,
		FirewallType:      "TPLink",
		Date:              date,
		Time:              time,
		TypeEvent:         typeEvent,
		LevelSignificance: levelSignificance,
		LogContent:        logContent,
		IPAddress:         ipAddress,
		MACAddress:        macAddress,
		Protocol:          protocol,
		Event:             event}
	logfilesTPLink = append(logfilesTPLink, log)
}

func parseDLinkString(line string) LogFileDLink {
	var lineSplit = strings.Split(line, " ")
	var date = lineSplit[0]
	var time = lineSplit[1]
	var category = lineSplit[2]
	var categoryID = lineSplit[3]
	var severity = lineSplit[4]
	var event = strings.Replace(regexp.MustCompile(`event=\S*`).FindString(line), "event=", "", -1)
	var action = strings.Replace(regexp.MustCompile(`action=\S*`).FindString(line), "action=", "", -1)
	var rule = strings.Replace(regexp.MustCompile(`rule=\S*`).FindString(line), "rule=", "", -1)
	var proto = strings.Replace(regexp.MustCompile(`connipproto=\S*`).FindString(line), "connipproto=", "", -1)
	var srcIf = strings.Replace(regexp.MustCompile(`connrecvif=\S*`).FindString(line), "connrecvif=", "", -1)
	var dstIf = strings.Replace(regexp.MustCompile(`conndestif=\S*`).FindString(line), "conndestif=", "", -1)
	var srcIP = strings.Replace(regexp.MustCompile(`connsrcip=\S*`).FindString(line), "connsrcip=", "", -1)
	var dstIP = strings.Replace(regexp.MustCompile(`conndestip=\S*`).FindString(line), "conndestip=", "", -1)
	var srcPort = strings.Replace(regexp.MustCompile(`connsrcport=\S*`).FindString(line), "connsrcport=", "", -1)
	var dstPort = strings.Replace(regexp.MustCompile(`conndestport=\S*`).FindString(line), "conndestport=", "", -1)

	var conn = strings.Replace(regexp.MustCompile(`conn=\S*`).FindString(line), "conn=", "", -1)
	var connnewsrcip = strings.Replace(regexp.MustCompile(`connnewsrcip=\S*`).FindString(line), "connnewsrcip=", "", -1)
	var connnewsrcport = strings.Replace(regexp.MustCompile(`connnewsrcport=\S*`).FindString(line), "connnewsrcport=", "", -1)
	var connnewdestip = strings.Replace(regexp.MustCompile(`connnewdestip=\S*`).FindString(line), "connnewdestip=", "", -1)
	var connnewdestport = strings.Replace(regexp.MustCompile(`connnewdestport=\S*`).FindString(line), "connnewdestport=", "", -1)
	var origsent = strings.Replace(regexp.MustCompile(`origsent=\S*`).FindString(line), "origsent=", "", -1)
	var termsent = strings.Replace(regexp.MustCompile(`termsent=\S*`).FindString(line), "termsent=", "", -1)
	var conntime = strings.Replace(regexp.MustCompile(`conntime=\S*`).FindString(line), "conntime=", "", -1)
	idCounter++

	return LogFileDLink{
		ID:              idCounter,
		FirewallType:    "DLink",
		Date:            date,
		Time:            time,
		Category:        category,
		CategoryID:      categoryID,
		Severity:        severity,
		Event:           event,
		Action:          action,
		Rule:            rule,
		Protocol:        proto,
		SrcIf:           srcIf,
		DstIf:           dstIf,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		SrcPort:         srcPort,
		DstPort:         dstPort,
		Conn:            conn,
		ConnNewSrcIp:    connnewsrcip,
		ConnNewSrcPort:  connnewsrcport,
		ConnNewDestIp:   connnewdestip,
		ConnNewDestPort: connnewdestport,
		OrigSent:        origsent,
		TermSent:        termsent,
		ConnTime:        conntime}
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
		parseTPLinkString(eachline)
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
	logfilesKaspersky = nil
	files, err := ioutil.ReadDir("./logfiles/kaspersky")

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		readKasperskyLogFile("./logfiles/kaspersky/" + f.Name())
	}
}

func loadTPLinkLogs() {
	logfilesTPLink = nil
	files, err := ioutil.ReadDir("./logfiles/tplink")

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		readTPLinkLogFile("./logfiles/tplink/" + f.Name())
	}
}

func loadDLinkLogs() {
	logfilesDLink = nil
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
	json.NewEncoder(w).Encode(append([]interface{}{}, logfilesKaspersky, logfilesTPLink, logfilesDLink))
}

func updateLogFilesKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadKasperskyLogs()
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

func updateLogFilesTPLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadTPLinkLogs()
	json.NewEncoder(w).Encode(logfilesTPLink)
}

func updateLogFilesDLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	loadDLinkLogs()
	json.NewEncoder(w).Encode(logfilesDLink)
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
		id, _ := strconv.Atoi(params["id"])
		if item.ID == id {
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
		id, _ := strconv.Atoi(params["id"])
		if item.ID == id {
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
		id, _ := strconv.Atoi(params["id"])
		if item.ID == id {
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
	r.HandleFunc("/api/logfiles/update/kaspersky", updateLogFilesKaspersky).Methods("GET")
	r.HandleFunc("/api/logfiles/update/tplink", updateLogFilesTPLink).Methods("GET")
	r.HandleFunc("/api/logfiles/update/dlink", updateLogFilesDLink).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}
