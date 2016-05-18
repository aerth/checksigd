/*

Copyright (c) 2016 aerth@sdf.org
https://github.com/aerth/checksigd

*/

package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"

	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/fcgi"

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
	// ErrNoReferer is returned when a HTTPS request provides an empty Referer
	// header.
	ErrNoReferer = errors.New("referer not supplied")
	// ErrBadReferer is returned when the scheme & host in the URL do not match
	// the supplied Referer header.
	ErrBadReferer = errors.New("referer invalid")
	// ErrNoToken is returned if no CSRF token is supplied in the request.
	ErrNoToken = errors.New("CSRF token not found in request")
	// ErrBadToken is returned if the CSRF token in the request does not match
	// the token in the session, or is otherwise malformed.
	ErrBadToken = errors.New("CSRF token invalid")
)
var (
	port       = flag.String("port", "8080", "HTTP Port to listen on")
	debug      = flag.Bool("debug", false, "be verbose, dont switch to debug.log")
	insecure   = flag.Bool("insecure", false, "accept insecure cookie transfer (http/80)")
	fastcgi    = flag.Bool("fastcgi", false, "use fastcgi with nginx")
	bind       = flag.String("bind", "127.0.0.1", "default: 127.0.0.1 - maybe 0.0.0.0 ?")
	help       = flag.Bool("help", false, "show usage help and quit")
	CSRF_TOKEN = []byte("")
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

	// Sanity Check
	SelfTest()

	if os.Getenv("CSRF_TOKEN") == "" {
		log.Println("CSRF_TOKEN not set. Using default.")
		CSRF_TOKEN = []byte("LI80PNK1xcT01jmQBsEyxyrNCrbyyFPjPU8CKnxwmCruxNijgnyb3hXXD3p1RBc0+LIRQUUbTtis6hc6LD4I/A==")
	} else {
		log.Println("CSRF key OK", os.Getenv("CSRF_TOKEN"))
		CSRF_TOKEN = []byte(os.Getenv("CSRF_TOKEN"))
	}

	//Begin Routing
	r := mux.NewRouter()

	r.NotFoundHandler = http.HandlerFunc(RedirectHomeHandler)

	r.HandleFunc("/", HomeHandler)

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
	if *fastcgi == true {
		listener, err := net.Listen("tcp", *bind+":"+*port)
		if err != nil {
			log.Fatal("Could not bind: ", err)
		}
		if *insecure == true {
			log.Fatal(fcgi.Serve(listener,
				csrf.Protect(CSRF_TOKEN,
					csrf.HttpOnly(true),
					csrf.Secure(false))(r)))
		} else {
			log.Println("info: https:// only")
			log.Fatal(fcgi.Serve(listener,
				csrf.Protect(CSRF_TOKEN,
					csrf.HttpOnly(true),
					csrf.Secure(true))(r)))
		}
	} else if *fastcgi == false && *insecure == true {
		log.Fatal(http.ListenAndServe(":"+*port,
			csrf.Protect(CSRF_TOKEN,
				csrf.HttpOnly(true),
				csrf.Secure(false))(r)))
	} else if *fastcgi == false && *insecure == false {
		log.Println("info: https:// only")
		log.Fatal(http.ListenAndServe(":"+*port,
			csrf.Protect(CSRF_TOKEN, csrf.HttpOnly(true),
				csrf.Secure(true))(r)))
	}

}

func SelfTest() {
	log.Println("Starting self test...")

	_, err := template.New("Index").ParseFiles("./templates/index.html")
	if err != nil {
		log.Println("Fatal: Template Error:", err)
		log.Fatal("Fatal: Template Error\n\n\t\tHint: Copy ./templates and ./static from $GOPATH/src/github.com/aerth/checksigd/ to the location of your binary.")
	}

	_, err = template.New("Error").ParseFiles("./templates/error.html")
	if err != nil {
		log.Println("Fatal: Template Error:", err)
		log.Fatal("Fatal: Template Error\nHint: Copy ./templates and ./static from $GOPATH/src/github.com/aerth/checksigd/ to the location of your binary.")
	}

	log.Println("Passed self test.")
}

// HomeHandler parses the ./templates/index.html template file.
// This returns a web page with a form, captcha, CSRF token, and the checksigd API key to send the message.
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
	t, err := template.New("Index").ParseFiles("./templates/index.html")
	if err != nil {
		log.Println("Almost fatal: Cant load index.html template!")
		log.Println(err)
		fmt.Fprintf(w, "We are experiencing some technical difficulties. Please come back soon!")
	} else {
		data := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		}

		t.ExecuteTemplate(w, "Index", data)

	}
}

// CustomErrorHandler allows checksigd administrator to customize the 404 Error page
// Using the ./templates/error.html file.
func CustomErrorHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("visitor: 404 %s - %s at %s", r.Host, r.UserAgent(), r.RemoteAddr)
	p := bluemonday.UGCPolicy()
	domain := getDomain(r)
	sanit := p.Sanitize(r.URL.Path[1:])
	log.Printf("404 on %s/%s", sanit, domain)
	t, err := template.New("Error").ParseFiles("./templates/error.html")
	if err == nil {
		data := map[string]interface{}{
			"err":            "404",
			csrf.TemplateTag: csrf.TemplateField(r),
		}
		t.ExecuteTemplate(w, "Error", data)
	} else {
		log.Printf("template error: %s at %s", r.UserAgent(), r.RemoteAddr)
		log.Println(err)
		http.Redirect(w, r, "/", 301)
	}
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
