package main

import (
	"encoding/json"
	"log"
	"net/http"

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
}

type LogFileTPLink struct {
	FirewallType      string `json:"firewallType"`
	ID                string `json:"id"`
	Date              string `json:"date"`
	Time              string `json:"time"`
	TypeEvent         string `json:"typeEvent"`
	LevelSignificance string `json:"levelSignificance"`
	LogContent        string `json:"logContent"`
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

// Get all logfiles of firewall
func getLogFilesKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

func getLogFilesTPLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

func getLogFilesDLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

// Get one logfile of firewall
func getLogFileKaspersky(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) // Get params
	// Loop through logFiles and fund with id
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
	params := mux.Vars(r) // Get params
	// Loop through logFiles and fund with id
	for _, item := range logfilesKaspersky {
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
	params := mux.Vars(r) // Get params
	// Loop through logFiles and fund with id
	for _, item := range logfilesKaspersky {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	var error = ErrorMessage{Error: "Not found"}
	json.NewEncoder(w).Encode(error)
}

// Update all logfiles in model
func updateLogFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfilesKaspersky)
}

func main() {
	// Init Router
	r := mux.NewRouter()

	// TODO: open and parse logfiles

	// logfilesKaspersky = append(logfiles, LogFileKaspersky{ID: "1", Date: "13.04.2018", Time: "20:46:19", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 111.231.68.208 на локальный порт 80"})
	// logfilesKaspersky = append(logfiles, LogFileKaspersky{ID: "2", Date: "13.04.2018", Time: "4:38:58", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 111.233.68.128 на локальный порт 80"})
	// logfilesKaspersky = append(logfiles, LogFileKaspersky{ID: "3", Date: "15.04.2018", Time: "12:32:05", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 122.11.11.22 на локальный порт 80"})
	// logfilesKaspersky = append(logfiles, LogFileKaspersky{ID: "4", Date: "16.04.2018", Time: "19:38:13", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 205.231.33.41 на локальный порт 80"})

	// make get and update /api/logfiles/kaspersky
	r.HandleFunc("/api/logfiles/kaspersky", getLogFilesKaspersky).Methods("GET")
	r.HandleFunc("/api/logfile/kaspersky/{id}", getLogFileKaspersky).Methods("GET")
	r.HandleFunc("/api/updatelogs/kaspersky", updateLogFiles).Methods("GET")

	// make get and update /api/logfiles/tplink
	r.HandleFunc("/api/logfiles/tplink", getLogFilesTPLink).Methods("GET")
	r.HandleFunc("/api/logfile/tplink/{id}", getLogFileTPLink).Methods("GET")
	r.HandleFunc("/api/updatelogs/tplink", updateLogFiles).Methods("GET")

	// make get and update /api/logfiles/dlink
	r.HandleFunc("/api/logfiles/dlink", getLogFilesDLink).Methods("GET")
	r.HandleFunc("/api/logfile/dlink/{id}", getLogFileDLink).Methods("GET")
	r.HandleFunc("/api/updatelogs/dlink", updateLogFiles).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}
