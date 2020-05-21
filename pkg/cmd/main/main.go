package main

import (
    "fmt"
    "log"
    "net/http"
    "net/https"
)

// test rest endpoint
func homePage(w http.ResponseWriter, r *http.Request){
    fmt.Fprintf(w, "Welcome to the HomePage!")
    fmt.Println("Endpoint Hit: homePage")
}

func handleRequests() {
    http.HandleFunc("/", homePage)
    log.Fatal(https.ListenAndServe(":9443", nil))
}

func main() {
	fmt.Println("entered main GO routine!")
    handleRequests()
}
