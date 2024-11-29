package pathfinder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/sirupsen/logrus"
)

/* Generated by LLM */

type Country struct {
	Name   string `json:"name"`
	ISO    string `json:"iso"`
	Threat int    `json:"threat"`
}

type ASN struct {
	ASN     int     `json:"asn"`
	Name    string  `json:"name"`
	Country Country `json:"country"`
	Threat  int     `json:"threat"`
}

type Organization struct {
	Name   string `json:"name"`
	Method string `json:"method"`
}

type Reserved struct {
	Name    string `json:"name"`
	Network string `json:"nework"`
}

type ArkPing struct {
	VP  string  `json:"vp"`
	RTT float64 `json:"rtt"`
}

type Geo struct {
	Method string `json:"method"`
}

type Hop struct {
	IP           string       `json:"ip"`
	ProbeTTL     int          `json:"probe_ttl"`
	ASN          ASN          `json:"asn"`
	Country      Country      `json:"country,omitempty"`
	Organization Organization `json:"organization"`
	Reserved     Reserved     `json:"reserved,omitempty"`
	ArkPing      ArkPing      `json:"arkping,omitempty"`
	Geo          Geo          `json:"geo,omitempty"`
	Hostname     string       `json:"hostname,omitempty"`
	Threat       int          `json:"threat"`
}

type Data struct {
	ID           int       `json:"id"`
	Src          string    `json:"src"`
	Dst          string    `json:"dst"`
	Hops         []Hop     `json:"hops"`
	Finished     bool      `json:"finished"`
	TimeCreated  time.Time `json:"time_created"`
	TimeModified time.Time `json:"time_modified"`
	Errors       []string  `json:"errors"`
}

type Response struct {
	TotalCount int      `json:"totalCount"`
	PageSize   int      `json:"pageSize"`
	Page       int      `json:"page"`
	Data       []Data   `json:"data"`
	Errors     []string `json:"errors"`
}

type Root struct {
	Data Data `json:"data"`
}

/* Fin */

type PFObj struct {
	Data   []int
	Errors []string
}

func Query(endpoint, apiKey string, identifier int, logger *logrus.Logger) (bool, *Response, error) {
	// now we do a lookup on the code
	endpoint2 := fmt.Sprintf("%s/%d?hops", endpoint, identifier)
	req2, err := http.NewRequest("GET", endpoint2, nil)
	if err != nil {
		return false, nil, err
	}

	if logger != nil {
		logger.Debugf("requesting: %s", endpoint2)
	}

	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("pathfinder-key", apiKey)

	// Send our request
	client := &http.Client{}
	resp2, err := client.Do(req2)
	if err != nil {
		return false, nil, err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusCreated {
		return false, nil, fmt.Errorf("Http POST failed with status code: %d", resp2.StatusCode)
	}

	body2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		return false, nil, err
	}

	if logger != nil {
		logger.Debugf("pathfinder: %s", body2)
	}

	responseData2 := &Response{}
	err = json.Unmarshal(body2, responseData2)
	if err != nil {
		return false, nil, err
	}

	if logger != nil {
		logger.Debugf("Response: %v", responseData2)
	}

	// TODO: it would be better if pathfinder set complete: true when it was done
	// but it doesnt.
	hops := 0
	for _, d := range responseData2.Data {
		for _, hop := range d.Hops {
			if logger != nil {
				logger.Debugf("Hop: %s, Threat: %d", hop.IP, hop.Threat)
			}
		}
		hops = hops + len(d.Hops)
	}

	if hops == 0 {
		return false, responseData2, nil
	}

	// we have atleast 1 hop somewhere
	return true, responseData2, nil
}

func Submit(endpoint, apiKey string, requestData []byte, logger *logrus.Logger) (bool, int, error) {

	jsonData := "[{\"data\":" + string(requestData) + "}]"

	var roots []Root
	err := json.Unmarshal([]byte(jsonData), &roots)
	if err != nil {
		return false, 0, err
	}

	backToByte, err := json.Marshal(roots)
	if err != nil {
		return false, 0, err
	}

	if logger != nil {
		logger.Debugf("Endpoint: %s  || Data: %#v", endpoint, roots)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(backToByte))
	if err != nil {
		return false, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("pathfinder-key", apiKey)

	if logger.GetLevel() == logrus.DebugLevel {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			logger.Debugf("Error dumping request: %v\n", err)
			return false, 0, err
		}
		logger.Debugf("HTTP Request:\n%s\n", string(reqDump))
	}

	// Send our request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if logger != nil {
		logger.Debugf("Response code: %d\n", resp.StatusCode)
	}

	// return code is a StatusCreated
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return false, 0, fmt.Errorf("Http POST failed with status code: %d", resp.StatusCode)
	}

	// The response code is an array of uuids for the traces
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	// response: {"data":[118140],"errors":[]}
	responseData := &PFObj{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return false, 0, err
	}

	d := responseData.Data
	code := 0
	for _, c := range d {
		code = int(c)
	}
	if len(responseData.Errors) > 0 {
		return false, 0, fmt.Errorf("pathfinder returned error: %v", responseData.Errors)
	}

	if logger != nil {
		logger.Debugf("Tracking Code: %d\n", code)
	}

	return true, code, nil
}

func SendRequest(endpoint, apiKey string, requestData []byte, logger *logrus.Logger) (bool, error) {

	ok, code, err := Submit(endpoint, apiKey, requestData, logger)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("got a bad value: %d", code)
	}

	ok, resp, err := Query(endpoint, apiKey, code, logger)
	if err != nil {
		return false, err
	}

	if logger != nil {
		logger.Debugf("Resp: %#v", resp)
	}

	return ok, nil
}
