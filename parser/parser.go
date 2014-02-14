package main

import (
    //"flag"
	//"log"
	//"net/http"
    "fmt"
    "regexp"
    "os"
    "bufio"
    "encoding/json"
    "net/url"
    "strings"
    //"sort"
)

type CSPReport struct {
    DocumentURI string `json:"document-uri"`
    ViolatedDirective string `json:"violated-directive"`
    OriginalPolicy string `json:"original-policy"`
    ReportURI string `json:"report-uri"`
    BlockedURI string `json:"blocked-uri"`
}

type CSPReportCollection struct {
    Report map[string]CSPReport
}

var reports []CSPReport

func readLines(filename string) ([]string, error) {
        fi, err := os.Open("etsy.log")
        if err != nil { 
            fmt.Printf("Cannot open file!") 
            panic(err) 
        }
        defer fi.Close()
        var lines []string
        scanner := bufio.NewScanner(fi)
        for scanner.Scan() {
                lines = append(lines, scanner.Text())
        }
        return lines, scanner.Err()
}

func (cspcoll *CSPReportCollection) FromJson(jsonStr string) error{
            var s = &cspcoll.Report
            //fmt.Printf("index :%i %s", index, lines[index])
            b := []byte(jsonStr)
            //fmt.Println("hey there")
            report := json.Unmarshal(b, s)
            //for k, v := range *s {
            //    fmt.Println("KEY: %s",k)
            //    fmt.Println("VALUE: %s", v.DocumentURI)
            //}
            //fmt.Println(s)
            return report
}

/*func addToPolicy(report CSPReportCollection) (error) {

        return
}*/

func ReverseArray(s []string) []string {
    reverse := make([]string, len(s))
    for _, test := range s {
        reverse = append(reverse, test) 
    }
    return reverse
}

func main() {
        policy := make(map[string][][]string)
        fmt.Println("Starting!")
        cspc := new(CSPReportCollection)
        lines, err := readLines("etsy.log")
        if err != nil {
                fmt.Printf("readLines: %s", err)
                panic(err)
        }
        //reports = make([]CSPReport, len(lines))
        fmt.Printf("file length: %v", len(lines))
        for _, line := range lines {
        //cspc.FromJson(`{"csp-report":{"document-uri":"http://www.etsy.com/","referrer":"","violated-directive":"style-src 'none'","effective-directive":"style-src","original-policy":"default-src 'none';script-src 'none';object-src 'none';img-src 'none';media-src 'none';style-src 'none';frame-src 'none';font-src 'none';connect-src 'none';report-uri /csp.php","blocked-uri":"http://site.etsystatic.com"}}`)
        cspc.FromJson(line)
        //fmt.Println(cspc.Report)
        for _,v := range cspc.Report {
        //    cspc.FromJson(lines[index])
            //fmt.Printf("report: %s", cspc.Pool)
            //fmt.Println("KEY: %s",k)
            u ,_ := url.Parse(v.DocumentURI)
            b ,_ := url.Parse(v.BlockedURI)
            //check to see if document-uri is the host we want.
            fmt.Printf("HOST: %s\n", u.Host)
            //regex. ugh.
            r , _ := regexp.Compile("www\\.etsy\\.com")
            //check if the violation report is for the host we care about
            if (r.MatchString(u.Host)) {
                fmt.Println("DOMAIN MATCH")
                components := strings.Split(v.ViolatedDirective, " ")
                fqdn := b.Scheme+ "." + b.Host
                urlcomponents := strings.Split(fqdn, ".")
                //sort.Reverse(urlcomponents)
                //fmt.Printf(components[0])
                fmt.Printf(fqdn)
                fmt.Printf(urlcomponents[0])
                //add the split url to the correct violation bucket
                policy[components[0]] = append(policy[components[0]], urlcomponents)
            }
        }
    }
    //fmt.Println(policy["script-src"])
}
