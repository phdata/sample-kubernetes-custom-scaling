package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

var LastUpdateTime time.Time
var CurrentReplicaRate int

func handler(w http.ResponseWriter, r *http.Request) {
	checkTime, _ := time.ParseDuration("120s")
	currentTimeDifference := time.Now().Sub(LastUpdateTime)
	log.Printf("Current replica rate to %d", CurrentReplicaRate)
	log.Printf("Difference in time is %+v", currentTimeDifference.Seconds())
	if currentTimeDifference >= checkTime {
		LastUpdateTime = time.Now()
		rand.Seed(time.Now().UTC().UnixNano())
		CurrentReplicaRate = randInt(1, 4)
		log.Printf("Changed the current replica rate to %d", CurrentReplicaRate)
	}

	fmt.Fprintf(w, "{\"replicas\":"+strconv.Itoa(CurrentReplicaRate)+"}")
	log.Printf("%s %s\n", r.Method, r.URL.Path)
}

func main() {
	LastUpdateTime = time.Now()
	CurrentReplicaRate = 2
	log.Printf("Listening on :8080\n")
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}
