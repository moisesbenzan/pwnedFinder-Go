package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/akamensky/argparse"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

const VERSION = "pwnedFinder-0.01"
const HibpBreachedApi = "https://haveibeenpwned.com/api/breachedaccount/"
const DatabasesToday = "https://www.databases.today/search-nojs.php"

// Start of ParserArgs

type ParserArgs struct {
	printVersion *bool
	target       *[]string
	findDumps    *bool
	targetFile   *string
}

// End of ParserArgs

// Start of HTTPRequest

type HTTPRequest struct {
	url        string
	headers    map[string]string
	parameters map[string]string
}

// End of HTTPRequest

// Start of HIBPResponse
type HIBPResponse struct {
	Name       string
	Title      string
	DumpURL    string
	IsVerified bool
}

func (data *HIBPResponse) isDownloadable() string {
	if len(data.DumpURL) > 0 {
		return "yes"
	}
	return "no"
}

func (data *HIBPResponse) isVerified() string {
	if data.IsVerified {
		return "yes"
	}

	return "no"
}

func (data *HIBPResponse) String() string {
	dumpString := fmt.Sprintf("\t\tShort name: %s\n\t\tLong name: %s\n", data.Name, data.Title)
	dumpString += fmt.Sprintf("\t\tVerified: %s\n\t\tDownloadable: %s\n", data.isVerified(), data.isDownloadable())

	if len(data.DumpURL) > 0 {
		dumpString += fmt.Sprintf("\t\tURL: %s\n", data.DumpURL)
	}

	return dumpString
}

func (data *HIBPResponse) addDumpURL(dUrl string) {
	data.DumpURL = dUrl
	return
}

// End of HIBPResponse

// Start of PwnedTarget
type PwnedTarget struct {
	Credentials string
	DumpsFound  []HIBPResponse
}

func (data *PwnedTarget) String() string {
	if len(data.DumpsFound) < 1 {
		return fmt.Sprintf("Report for %s: \n\tResults: Not breached.", data.Credentials)
	}

	summaryString := fmt.Sprintf("Report for %s: \n\tResults: Breached. \n\tFound %d dumps.\n", data.Credentials, len(data.DumpsFound))
	for idx, dump := range data.DumpsFound {
		summaryString += fmt.Sprintf("\tDump report #%d\n", idx)

		summaryString = summaryString + dump.String()
	}

	return summaryString
}

//End of PwnedTarget

func initParser() ParserArgs {
	// Create new parser object
	parser := argparse.NewParser("pwnedFinder", "Find in which dumps the Credentials (username/email) provided is pwned.")
	args := ParserArgs{}

	// Declare all the args
	args.findDumps = parser.Flag("D", "find-dumps", &argparse.Options{Help: "Attempts to find a downloadable dump containing the target's password or hash", Default: false})
	args.printVersion = parser.Flag("V", "version", &argparse.Options{Help: "Prints the version information and exits."})
	args.target = parser.List("t", "target", &argparse.Options{Help: "List of targets to search for pwned Credentials."})
	args.targetFile = parser.String("T", "target-file", &argparse.Options{Help: "Loads targets from a file."})

	// Parse input
	err := parser.Parse(os.Args)

	if (err != nil) || (len(os.Args) < 2) {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	if *args.printVersion {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	return args

}

func createHttpRequest(RequestObject *HTTPRequest) *http.Request {

	req, err := http.NewRequest(http.MethodGet, RequestObject.url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Headers
	for key, value := range RequestObject.headers {
		req.Header.Set(key, value)
	}

	// Add http params
	queryString := req.URL.Query()

	for key, value := range RequestObject.parameters {
		queryString.Add(key, value)
	}

	req.URL.RawQuery = queryString.Encode()

	//Return request object
	return req

}

func checkPwned(Target *PwnedTarget) {

	client := http.Client{}
	HttpReq := HTTPRequest{
		url: HibpBreachedApi + url.QueryEscape(Target.Credentials),
		headers: map[string]string{
			"User-Agent":  VERSION,
			"api-version": "2",
		},
		parameters: map[string]string{
			"truncateResponse": "false",
		},
	}

	req := createHttpRequest(&HttpReq)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Errored whiled doing a request.")
		return
	}

	defer resp.Body.Close()
	resBody, _ := ioutil.ReadAll(resp.Body)

	var data []HIBPResponse
	json.Unmarshal(resBody, &data)

	Target.DumpsFound = data
	return
}

func _searchDumps(source *HIBPResponse) {
	client := http.Client{}

	HttpReq := HTTPRequest{
		url: DatabasesToday,
		headers: map[string]string{
			"User-Agent": VERSION,
		},
		parameters: map[string]string{
			"for": url.QueryEscape(source.Name),
		},
	}

	req := createHttpRequest(&HttpReq)

	resp, err := client.Do(req)
	defer resp.Body.Close()

	if err != nil {
		fmt.Println("Errored whiled doing a request.")
		return
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	tRow := doc.Find("#myTable tr").Slice(1, goquery.ToEnd).First()

	dumpUrl := tRow.Find("a").AttrOr("href", "")
	//fmt.Println(dumpUrl)

	source.DumpURL = dumpUrl
	return

}

func searchDumps(Target *PwnedTarget) {

	for index, _ := range Target.DumpsFound {
		_searchDumps(&Target.DumpsFound[index])
	}
}

func loadTargetsFromFile(targetFile *string) []string {

	file, err := os.Open(*targetFile)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()
	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		targets = append(targets, scanner.Text())
	}

	return targets
}

func main() {

	parsedArgs := initParser()

	//Finally print the collected string
	//fmt.Println(len(*parsedArgs.targetFile))
	var runTargets []string

	if len(*parsedArgs.targetFile) != 0 {
		// TODO fix this condition
		runTargets = loadTargetsFromFile(parsedArgs.targetFile)
	} else {
		runTargets = *parsedArgs.target
	}

	for _, target := range runTargets {
		currentTarget := PwnedTarget{target, nil}
		checkPwned(&currentTarget)
		if *parsedArgs.findDumps {
			searchDumps(&currentTarget)
		}
		fmt.Println(currentTarget.String())
	}

}
