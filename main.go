package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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
	Action            string `json:"action"`
}

type LogFileDLink struct {
	FirewallType string `json:"firewallType"`
	ID           string `json:"id"`
	Date         string `json:"date"`
	Time         string `json:"time"`
}

var logfilesKaspersky []LogFileKaspersky
var logfilesTPLink []LogFileTPLink
var logfilesDLink []LogFileDLink

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

	return LogFileKaspersky{ID: "1", FirewallType: "Kaspersky", Date: date, Time: time, Description: description, ProtectType: protectType, Application: application, Result: result, ObjectAttack: objectAttack}
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

func parseTPLinkString(line string) LogFileTPLink {
	var lineSplit = strings.Split(line, "\t")
	var date = lineSplit[0]
	var time = lineSplit[0]
	var typeEvent = lineSplit[1]
	var levelSignificance = lineSplit[2]
	var logContent = lineSplit[3]

	return LogFileTPLink{ID: "1", FirewallType: "TPLink", Date: date, Time: time, TypeEvent: typeEvent, LevelSignificance: levelSignificance, LogContent: logContent}
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

func parseDLinkString(line string) LogFileDLink {
	return LogFileDLink{ID: "1", FirewallType: "DLink", Date: "13.04.2018", Time: "20:46:19" + line}
}

func loadLogFiles() {
	loadKasperskyLogs()
	loadTPLinkLogs()
	loadDLinkLogs()
}

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
