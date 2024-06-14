package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const arLogFile = "active-responses.log"

//const arLogFile = "/var/ossec/logs/active-responses.log"

type WazuhResult struct {
	Matched bool      `json:"matched"`
	Event   MispEvent `json:"misp_event"`
}

type MispResult struct {
	Response []MispResponse `json:"response"`
}

type MispResponse struct {
	Event MispEvent `json:"Event"`
}

type MispEvent struct {
	Id             string       `json:"id"`
	Uuid           string       `json:"uuid"`
	Date           string       `json:"date"`
	ThreatLevel    string       `json:"threat_level_id"`
	Info           string       `json:"info"`
	AttributeCount string       `json:"attribute_count"`
	Objects        []MispObject `json:"Object"`
}

type MispObject struct {
	Name       string          `json:"name"`
	Desc       string          `json:"description"`
	Comment    string          `json:"comment"`
	Attributes []MispAttribute `json:"Attribute"`
}

type MispAttribute struct {
	Type           string `json:"type"`
	ObjectRelation string `json:"object_relation"`
	Value          string `json:"value"`
}

// find the first misp object contained in the given event with the specified name
// ex: malware-analysis
func getMispObject(name string, event *MispEvent) (*MispObject, bool) {

	for _, obj := range event.Objects {

		if obj.Name == name {
			return &obj, true
		}
	}
	return nil, false
}

// filter the wanted fields from the MispObject
func extractMispObjectInfo(m *MispObject, filter map[string]bool, c chan<- map[string]string) {

	//check if filter is not empty, if so set a flag
	var isFilterSet = filter != nil

	var info map[string]string = make(map[string]string)

	for _, attr := range m.Attributes {
		switch isFilterSet {

		case true:
			_, ok := filter[attr.ObjectRelation]
			if ok {
				info[attr.ObjectRelation] = attr.Value
			}

		case false:
			info[attr.ObjectRelation] = attr.Value
		}
	}
	c <- info

}

// generate a minimal response containing information about the matched indicator.
func generateWazuhResponse(m *MispResult) (map[string]any, error) {

	var wazuhResponse map[string]any = make(map[string]any)

	var tmpEvent MispEvent = m.Response[0].Event

	wazuhResponse["info"] = tmpEvent.Info
	wazuhResponse["date"] = tmpEvent.Date
	wazuhResponse["id"] = tmpEvent.Id
	wazuhResponse["uuid"] = tmpEvent.Uuid
	wazuhResponse["threat_level"] = tmpEvent.ThreatLevel

	malwareAnalysisObj, found := getMispObject("malware-analysis", &tmpEvent)
	if !found {
		return nil, errors.New("event doesn't contain any malware-analysis object")
	}

	analysisChan := make(chan map[string]string)
	go extractMispObjectInfo(malwareAnalysisObj, nil, analysisChan)

	malwareObj, found := getMispObject("malware", &tmpEvent)
	if !found {
		return nil, errors.New("event doesn't contain any malware object")
	}

	malwareFieldsFilter := map[string]bool{
		"name":         true,
		"malware_type": true,
	}

	malwareChan := make(chan map[string]string)
	go extractMispObjectInfo(malwareObj, malwareFieldsFilter, malwareChan)

	for i := 0; i < 2; i++ {

		select {
		case info1 := <-analysisChan:
			wazuhResponse["Malware_analysis"] = info1
		case info2 := <-malwareChan:
			wazuhResponse["Malware"] = info2
		}
	}

	return wazuhResponse, nil

}

// searches for the given key value inside a slice of attributes.
// Used to find values that are going to be sent back to wazuh as result
func findValue(key string, attributes []MispAttribute) string {

	var value string

	for _, attr := range attributes {

		if attr.ObjectRelation == key {
			value = attr.Value
			return value
		}
	}
	return ""

}

// extract the just added file name from the given log line
func extractFileName(s string) (string, bool) {

	var tmp string = strings.ReplaceAll(s, "\n", " ")

	startIndex := strings.LastIndex(tmp, "\\")
	if startIndex == -1 {
		return "", false
	}
	startIndex++

	endIndex := strings.LastIndex(tmp[startIndex:], "'")
	if endIndex == -1 {
		return "", false
	}
	endIndex += startIndex

	return tmp[startIndex:endIndex], true

}

type RequestConf struct {
	Url           string `mapstructure:"url"`
	ContentType   string `mapstructure:"content_type"`
	Authorization string `mapstructure:"authorization"`
	ReturnFormat  string `mapstructure:"return_format"`
}

func mispSearchRequest(filename string, requestConf *RequestConf) ([]byte, error) {

	url := requestConf.Url

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	contentType := requestConf.ContentType
	authorization := requestConf.Authorization

	// build query string
	var queryString map[string]interface{} = make(map[string]interface{})

	queryString["searchall"] = filename
	queryString["returnFormat"] = requestConf.ReturnFormat

	b, err := json.Marshal(queryString)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		fmt.Println(err)
		return []byte(""), err
	}
	// add required headers
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", authorization)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return []byte(""), err

	}
	defer resp.Body.Close()

	//read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte(""), err
	}

	return body, nil

}

func main() {

	f, err := os.OpenFile(arLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)

	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Print("match-indicator started")

	//read config file into struct
	var reqConf RequestConf
	if err = readConfig(&reqConf); err != nil {
		panic(err)
	}

	//parse the json input passed by wazuh
	fullLog, err := readWazuhInput()
	//fullLog := "File 'c:\\windows\\system32\\sru\\srudb.dat' added Mode: scheduled"

	if err != nil {
		panic(err)
	}
	log.Print("DEBUG| successfully parsed wazuh input")

	// extract the filename contained in the wazuh log
	filename, ok := extractFileName(fullLog)
	if !ok {
		log.Print("extract filename failed")
		return
	}
	log.Printf("filename found: %v", filename)

	// filename = "pafish.exe"
	body, err := mispSearchRequest(filename, &reqConf)
	if err != nil {
		log.Printf("ERROR | misp request failed: %v", err)
		panic(err)
	}

	// fmt.Println(string(body))

	var result MispResult
	if err = json.Unmarshal(body, &result); err != nil {
		panic(err)
	} else if result.Response == nil || len(result.Response) == 0 {
		log.Printf("no matching attribute found for the given filename")
		return
	}

	// create a new object which is going to be marshaled and sent back to wazuh
	wazuhResponse, err := generateWazuhResponse(&result)
	if err != nil {
		panic(err)
	}

	data, err := json.Marshal(wazuhResponse)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

}

// read json from stdin
func readInput() string {

	var line string
	s := bufio.NewScanner(os.Stdin)
	s.Scan()

	line = s.Text()

	return line

}

// read config file into the given struct
func readConfig(conf *RequestConf) error {

	viper.SetConfigName("conf")
	viper.SetConfigType("toml")

	viper.AddConfigPath("$HOME/go_misp")

	err := viper.ReadInConfig()
	if err != nil {
		log.Printf("ERROR | error while reading config file: %v", err)
		return err
	}
	log.Printf("DEBUG | successfully read config file")

	if err := viper.Unmarshal(conf); err != nil {
		log.Printf("ERROR | error while unmarshaling config: %v", err)
		return err
	}
	log.Printf("DEBUG | successfully unmarshaled config")
	return nil

}

func readWazuhInput() (string, error) {

	//read input from stdin
	jsonInput := readInput()
	log.Printf("DEBUG | jsonInput: %v", jsonInput)

	//unmarshal it into a map
	var alertContent *map[string]any
	alertContent, err := ParseWazuhArg(&jsonInput)

	if err != nil {
		log.Printf("error during ParseWazuhArg: %v", err)
		return "", err
	}

	//now extract the full_log field
	var fullLog string = (*alertContent)["full_log"].(string)
	return fullLog, nil

}
