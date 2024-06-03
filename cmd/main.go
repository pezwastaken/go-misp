package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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

func main() {

	// word to search for
	filename := "pafish.exe"

	url := "https://localhost/events/restSearch"

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	contentType := "application/json"
	authorization := "1E2kB3EwEd1XTw7u25yuh8ALsKZseTXJ2StErfmk"

	// build query string
	var queryString map[string]interface{} = make(map[string]interface{})

	queryString["searchall"] = filename
	queryString["returnFormat"] = "json"

	b, err := json.Marshal(queryString)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		fmt.Println(err)
		return
	}
	// add required headers
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", authorization)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	//read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// fmt.Println(string(body))

	var result MispResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		panic(err)
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

	//send data back
	fmt.Println(string(data))

}
