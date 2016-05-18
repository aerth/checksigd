// checksigd is a API server that returns file integrity signatures.

/*

Copyright (c) 2016 aerth@sdf.org
https://github.com/aerth/checksigd

*/

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/gorilla/mux"

	"log"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/microcosm-cc/bluemonday"

	"os"
	"time"
)

var version = "git"

const (
	maxbytes = 1024 // 1MiB
	text     = "text/plain"
)

//usage shows how available flags.
func usage() {
	fmt.Println("checksigd - version " + version)
	fmt.Println("\nusage: checksigd [flags]")
	fmt.Println("\nflags:")
	flag.PrintDefaults()
	fmt.Println("\nExample: checksigd -debug")
}

var (
	port  = flag.String("port", "8080", "HTTP Port to listen on")
	debug = flag.Bool("debug", false, "be verbose, dont switch to debug.log")
	//	fastcgi = flag.Bool("fastcgi", false, "use fastcgi with nginx")
	bind = flag.String("bind", "127.0.0.1", "default: 127.0.0.1 - maybe 0.0.0.0 ?")
	help = flag.Bool("help", false, "show usage help and quit")
)

// Return the domain the user requested us at
func getDomain(r *http.Request) string {
	type Domains map[string]http.Handler
	hostparts := strings.Split(r.Host, ":")
	requesthost := hostparts[0]
	return requesthost
}

//getLink returns the requested bind:port or http://bind:port string
func getLink(bind string, port string) string {

	link := "http://" + bind + ":" + port
	return link

}
func main() {

	// Set flags from command line
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	// Count extra non -flags
	if len(args) > 0 {
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

	log.Printf("[checksigd version " + version + "] live on " + getLink(*bind, *port))

	if *debug == false {
		log.Println("[switching logs to debug.log]")
		OpenLogFile()
	} else {
		log.Println("Debug on: [not using debug.log]")
	}
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

// not implemented yet
type HashRequest struct {
	url  string
	hash string
}

// Transport
var tr = &http.Transport{
	DisableCompression: true,
}

// Client
var apigun = &http.Client{
	CheckRedirect: redirectPolicyFunc,
	Transport:     tr,
}

// Keep useragent on redirect
func redirectPolicyFunc(req *http.Request, reqs []*http.Request) error {
	req.Header.Set("User-Agent", "checksigd/0.1")
	return nil
}

// HashHandler parses a POST request, gets and returns the first 1024 bytes.
func HashHandler(w http.ResponseWriter, r *http.Request) {

	// Limit request to 256 bytes, good enough for a URL ( testing with 76 byte URL and its not particularly short )
	r.Body = http.MaxBytesReader(w, r.Body, 256)

	// Send the rest to /dev/null
	log.Println(io.Copy(ioutil.Discard, r.Body))

	// todo: This should be equal to the domain name advertised.
	domain := getDomain(r)

	// Log the request
	log.Printf("HOME: %s /%s %s - %s",
		domain,
		r.RemoteAddr,
		r.Host,
		r.UserAgent())

	// Parse the user's request.
	r.ParseForm()

	// Typical request:
	// curl -d url=<http://example.com/md5.txt> https://checksigd.example.org
	if r.FormValue("url") == "" {
		w.Write([]byte("doing it wrong"))
		return
	}

	if r.FormValue("url") != "" {

		u, err := url.Parse(r.FormValue("url"))
		if err != nil {
			log.Println(err)
			return
		}

		// todo:
		// log.Println("Asking peers")
		// askpeers(r.FormValue("url"))

		// Create http request to send
		log.Println("Grabbing", u)
		z := &http.Request{
			Method: "GET",
			URL:    u,
			Header: http.Header{
				"User-Agent": {"checksigd/0.1"},
			},
		}

		// Limit to 1MiB
		z.Body = http.MaxBytesReader(w, z.Body, 1024)

		// Send request to alien server
		resp, err := apigun.Do(z)
		if err != nil {
			log.Println(err)
			return
		}

		// Limit to 1MiB
		resp.Body = http.MaxBytesReader(w, resp.Body, 1024)

		// Limit our response to 1024 bytes
		out := io.LimitReader(resp.Body, 1024)

		// Copy bytes from temporary buffer to browser/curl
		if _, err := io.Copy(w, out); err != nil {
			log.Println(err)
			return
		}

		// If we made it this far, we ran into no problems.
		log.Println("Gave signature.")
		return

	}

	fmt.Fprintf(w, "yo dawg, you were tryin to check the hash...\n")

}

// RedirectHomeHandler redirects everyone home ("/") with a 301 redirect.
func RedirectHomeHandler(rw http.ResponseWriter, r *http.Request) {
	p := bluemonday.UGCPolicy()
	domain := getDomain(r)
	sanit := p.Sanitize(r.URL.Path[1:])
	log.Printf("RDR: %s /%s %s - %s - %s", domain, sanit, r.RemoteAddr, r.Host, r.UserAgent())
	http.Redirect(rw, r, "/", 301)

}

func init() {
	rand.Seed(time.Now().UnixNano())
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
