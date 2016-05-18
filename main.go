/*

Copyright (c) 2016 aerth@sdf.org
https://github.com/aerth/checksigd

*/

package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/gorilla/mux"

	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"

	"github.com/microcosm-cc/bluemonday"

	"os"
	"strings"
	"time"
)

//usage shows how available flags.
func usage() {
	fmt.Println("\nusage: checksigd [flags]")
	fmt.Println("\nflags:")
	time.Sleep(1000 * time.Millisecond)
	flag.PrintDefaults()
	time.Sleep(1000 * time.Millisecond)
	fmt.Println("\nExample: checksigd -insecure -port 8080 -fastcgi -debug")
}

var (
	port    = flag.String("port", "8080", "HTTP Port to listen on")
	debug   = flag.Bool("debug", false, "be verbose, dont switch to debug.log")
	fastcgi = flag.Bool("fastcgi", false, "use fastcgi with nginx")
	bind    = flag.String("bind", "127.0.0.1", "default: 127.0.0.1 - maybe 0.0.0.0 ?")
	help    = flag.Bool("help", false, "show usage help and quit")
)

func main() {

	// Set flags from command line
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) > 1 {
		usage()
		os.Exit(2)
	}

	//Begin Routing
	r := mux.NewRouter()
	r.NotFoundHandler = http.HandlerFunc(RedirectHomeHandler)
	r.HandleFunc("/", HomeHandler).
		Methods("GET")

	r.HandleFunc("/", HashHandler).
		Methods("POST")
	//	Host("https://checksigd.herokuapp.com")

	http.Handle("/", r)
	//End Routing
	if *debug == false {
		log.Println("[switching logs to debug.log]")
		OpenLogFile()
	} else {
		log.Println("Debug on: [not using debug.log]")
	}
	log.Printf("[checksigd] live on " + getLink(*fastcgi, *bind, *port))
	// Start Serving!
	log.Fatal(http.ListenAndServe(":"+*port, r))

}

//  checksigd blank page (tm)
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	p := bluemonday.UGCPolicy()
	domain := getDomain(r)
	sanit := p.Sanitize(r.URL.Path[1:])
	log.Printf("HOME: %s /%s %s - %s - %s",
		domain,
		sanit,
		r.RemoteAddr,
		r.Host,
		r.UserAgent())

}

type HashRequest struct {
	url  string
	hash string
}

// Set User Agent
var tr = &http.Transport{
	DisableCompression: true,
}
var apigun = &http.Client{
	CheckRedirect: redirectPolicyFunc,
	Transport:     tr,
}

func redirectPolicyFunc(req *http.Request, reqs []*http.Request) error {
	req.Header.Add("Content-Type", "[application/json; charset=utf-8")
	req.Header.Set("User-Agent", "checksigd/0.1")
	return nil
}

// HashHandler parses a POST request, gets and returns the first 64 bytes.
func HashHandler(w http.ResponseWriter, r *http.Request) {
	//	p := bluemonday.UGCPolicy()
	domain := getDomain(r)
	log.Printf("HOME: %s /%s %s - %s - %s",
		domain,
		r.RemoteAddr,
		r.Host,
		r.UserAgent())

	r.ParseForm()

	if r.FormValue("url") != "" {
		//	w.Write([]byte("url is " + r.FormValue("url") + "..."))
		u, err := url.Parse(r.FormValue("url"))
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Grabbing", u)
		request := &http.Request{
			Method: "GET",
			URL:    u,
			Header: http.Header{
				"User-Agent": {"checksigd/0.1"},
			},
		}
		resp, err := apigun.Do(request)
		out := io.LimitReader(resp.Body, 1024)
		if _, err := io.Copy(w, out); err != nil {
			log.Println(err)
			return
		}

		//fmt.Fprintf(w, "%q", p.Sanitize(string(out)))

		return
	}
	// checkURL()
	// downloadSUM() // first 64 bytes of URL body
	// validate nospaces
	// return SUM
	// simple!

	fmt.Fprintf(w, "yo dawg, you were tryin to check the hash...\n")

}

// RedirectHomeHandler redirects everyone home ("/") with a 301 redirect.
func RedirectHomeHandler(rw http.ResponseWriter, r *http.Request) {
	p := bluemonday.UGCPolicy()
	domain := getDomain(r)
	sanit := p.Sanitize(r.URL.Path[1:])
	log.Printf("RDR: %s /%s %s - %s - %s", domain, sanit, r.RemoteAddr, r.Host, r.UserAgent())
	//log.Printf("RDR %s %s", lol, domain)
	http.Redirect(rw, r, "/", 301)

}

func getDomain(r *http.Request) string {
	type Domains map[string]http.Handler
	hostparts := strings.Split(r.Host, ":")
	requesthost := hostparts[0]
	return requesthost
}
func getSubdomain(r *http.Request) string {
	type Subdomains map[string]http.Handler
	hostparts := strings.Split(r.Host, ":")
	requesthost := hostparts[0]
	if net.ParseIP(requesthost) == nil {
		log.Println("Requested domain: " + requesthost)
		domainParts := strings.Split(requesthost, ".")
		log.Println("Subdomain:" + domainParts[0])
		if len(domainParts) > 2 {
			if domainParts[0] != "127" {
				return domainParts[0]
			}
		}
	}
	return ""
}

// serverSingle just shows one file.
func serveSingle(pattern string, filename string) {
	http.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	})
}

// Key Generator
func init() {
	rand.Seed(time.Now().UnixNano())
}

var runes = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890123456789012345678901234567890")

//GenerateAPIKey does API Key Generation with the given runes.
func GenerateAPIKey(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}

//OpenLogFile switches the log engine to a file, rather than stdout
func OpenLogFile() {
	f, err := os.OpenFile("./debug.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file: %v", err)
		log.Fatal("Hint: touch ./debug.log, or chown/chmod it so that the checksigd process can access it.")
		os.Exit(1)
	}
	log.SetOutput(f)
}

//getLink returns the requested bind:port or http://bind:port string
func getLink(fastcgi bool, bind string, port string) string {
	if fastcgi == true {
		link := bind + ":" + port
		return link
	} else {
		link := "http://" + bind + ":" + port
		return link
	}
}
