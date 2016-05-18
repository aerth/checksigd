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
	maxbytes   = 256 // our buffer limit is 256 bytes per request.
	maxurlsize = 127 // we grab from urls no longer than 127 chars
	maxtimeget = 3   // seconds
	text       = "text/plain"
	htmlhead   = `
	<!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style type="text/css">
        html, body, iframe { margin: 0; padding: 0; height: 100%; }
        iframe { display: block; width: 100%; border: none; }
      </style>
    <title>getsigd(1)</title>
    <body>
	`

	htmlfoot = `
	</body>
    </html>	
	`
	logolink = `<div style="text-align:center; width:100%; padding: 10px; padding-top:10vh;">
				<a href="https://github.com/aerth/checksigd"><img alt="checksigd(1)" src="data:image/png;base64,` + logo + `" />`
	homepage = htmlhead + logolink + htmlfoot
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

	fmt.Fprintf(w, "%s", homepage)

}

// not implemented yet
type HashRequest struct {
	url  string
	hash string
}

type HashRequester struct {
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

	domain := getDomain(r)

	// Send the rest to /dev/null
	//log.Println(io.Copy(ioutil.Discard, r.Body))

	// todo: This should be equal to the domain name advertised.

	// Log the request
	log.Printf("POST: %s /%s %s - %s",
		domain,
		r.RemoteAddr,
		r.Host,
		r.UserAgent())

	// Parse the user's request.
	r.ParseForm()

	// Typical request:
	// curl -d url=<http://example.com/md5.txt> https://checksigd.example.org
	//	if r.FormValue("url") != "" {

	// Check if it is a URL
	sigurl, err := url.Parse(r.FormValue("url"))
	if err != nil {
		log.Println("errrrr")
		log.Println(err)
		return
	}

	if len(sigurl.String()) > maxurlsize {
		log.Println("Too long.")
		log.Println(len(sigurl.String()), " > ", maxurlsize)
		return
	}

	// todo:
	// log.Println("Asking peers")
	// askpeers(r.FormValue("url"))

	// Create http request to send
	log.Println("Grabbing", sigurl)
	zr := &http.Request{
		Method: "GET",
		URL:    sigurl,
		Header: http.Header{
			"User-Agent": {"checksigd/0.1"},
		},
	}

	// Limit to 1MiB
	//	zr.Body = http.MaxBytesReader(w, zr.Body, 1024)

	// Send request to alien server
	resp, err := apigun.Do(zr)
	if err != nil {
		log.Println(err)
		return
	}

	// Log header
	// log.Println(resp.Header)

	// Check content-type header var for text/plain
	if http.CanonicalHeaderKey(resp.Header.Get("content-type")) != text {
		log.Printf("Not giving it! %s != %s", http.CanonicalHeaderKey(resp.Header.Get("content-type")), text)
		return
	} else {
		log.Println("Looks good!")
	}
	// Limit grab into mem
	resp.Body = http.MaxBytesReader(w, resp.Body, maxbytes)

	// Limit our response
	out := io.LimitReader(resp.Body, maxbytes)

	// Copy bytes from temporary buffer to browser/curl
	if _, err := io.Copy(w, out); err != nil {
		log.Println(err)
		return
	}

	// If we made it this far, we ran into no problems.
	log.Println("Gave signature.")
	return

	//	}

	//	fmt.Fprintf(w, "yo dawg, you were tryin to check the hash...\n")

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
