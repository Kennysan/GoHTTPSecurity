package main

import (
    "flag"
	"github.com/elazarl/goproxy"
	"log"
	"net/http"
    "fmt"
    "regexp"
    "os"
    "encoding/json"
)

type test_struct struct {
    Report []struct {
        Name    string
        Value   string
    }
}

func main() {
    hostptr := flag.String("host", `www\.etsy\.com`, "host to add security headers to")
    portptr := flag.String("port", "8080", "port to listen over")
    reportptr := flag.String("reporturi", "/beacon/csp.php", "report uri for CSP/X-XSS-Protection")
    logptr := flag.String("log", "proxy.log", "Logging file")
    //blockptr := flag.Bool("block", false, "blocking mode for security headers")
    //cspptr := flag.String("csp", "", "Set the content security policy")
    flag.Parse()
    f, err := os.OpenFile(*logptr, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("error opening file: %v", err)
        }
    defer f.Close()
    log.SetOutput(f)

    fmt.Println("Starting proxy")
	proxy := goproxy.NewProxyHttpServer()

    proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
         //fmt.Println("THIS IS SSL ON " + ctx.Req.Host)
         return goproxy.MitmConnect, host
     })
   //note:fix hostptr so periods and such are escaped. 
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(*hostptr))).DoFunc(
        func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)        {
            fmt.Println("INTERCEPTING\n\n")
            fmt.Println("HOST " + ctx.Req.Host)
            return r, nil
        })

    proxy.OnRequest(goproxy.UrlIs(*hostptr, *reportptr)).DoFunc(
        func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
            if r.Method == "POST" {
                var f interface{}
                decoder := json.NewDecoder(r.Body)
                _ = decoder.Decode(&f)
                fmt.Println("TEST:")
                m := f.(map[string]interface{})
                for k, v := range m {
                    switch vv := v.(type) {
                    case string:
                        fmt.Println("Key:" + string(k) + " Valuetype:" + string(vv))
                    case []interface{}:
                        fmt.Println("I AM A STRUCT")
                    default:
                        fmt.Println("ERROR")
                        }
                }
                fmt.Println("\n\n")
            }
            return r, nil
        })
    
    proxy.OnResponse().DoFunc(
        func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response{
            fmt.Println("RESPONSE\n\n")
            resp.Header.Set("Content-Security-Policy", "default-src 'self'; report-uri " + *reportptr)
            return resp
    })


	proxy.Verbose = true
	log.Fatal(http.ListenAndServe(":" + *portptr, proxy))
}
