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

// Log file Struct (Model)
type LogFile struct {
	ID           string `json:"id"`
	Date         string `json:"date"`
	Time         string `json:"time"`
	Description  string `json:"description"`
	ProtectType  string `json:"protectType"`
	Application  string `json:"application"`
	Result       string `json:"result"`
	ObjectAttack string `json:"objectAttack"`
}

var logfiles []LogFile

func getLogFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logfiles)
}

func getLogFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) // Get params
	// Loop through logFiles and fund with id
	for _, item := range logfiles {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	var error = ErrorMessage{Error: "Not found"}
	json.NewEncoder(w).Encode(error)
}

func main() {
	// Init Router
	r := mux.NewRouter()

	// TODO: open and parse logfiles

	logfiles = append(logfiles, LogFile{ID: "1", Date: "13.04.2018", Time: "20:46:19", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 111.231.68.208 на локальный порт 80"})
	logfiles = append(logfiles, LogFile{ID: "2", Date: "13.04.2018", Time: "4:38:58", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 111.233.68.128 на локальный порт 80"})
	logfiles = append(logfiles, LogFile{ID: "3", Date: "15.04.2018", Time: "12:32:05", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 122.11.11.22 на локальный порт 80"})
	logfiles = append(logfiles, LogFile{ID: "4", Date: "16.04.2018", Time: "19:38:13", Description: "Обнаружена сетевая атака", ProtectType: "Защита от сетевых атак", Application: "Неизвестно", Result: "Запрещено: Intrusion.Win.CVE-2017-7269.cas.exploit", ObjectAttack: "TCP от 205.231.33.41 на локальный порт 80"})

	// Route Handlers / Endpoints
	r.HandleFunc("/api/logfiles", getLogFiles).Methods("GET")
	r.HandleFunc("/api/logfile/{id}", getLogFile).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}
