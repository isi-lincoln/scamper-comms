package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/isi-lincoln/scamper-comms/pathfinder"
	log "github.com/sirupsen/logrus"
)

// LLMs generated code in this file
// Country represents a country with a code and a friendliness score
type Country struct {
	Name   string
	Code   string
	Threat int
}

var (
	// List of countries in the Americas with their friendliness scores
	// LLM
	countries = []Country{
		{"United States", "USA", 0},
		{"Canada", "CAN", 0},
		{"Mexico", "MEX", 2},
		{"Brazil", "BRA", 4},
		{"Argentina", "ARG", 3},
		{"Colombia", "COL", 5},
		{"Chile", "CHL", 2},
		{"Peru", "PER", 5},
		{"Uruguay", "URY", 2},
		{"Ecuador", "ECU", 5},
		{"Bolivia", "BOL", 6},
		{"Paraguay", "PRY", 5},
		{"Guyana", "GUY", 4},
		{"Suriname", "SUR", 4},
		{"Panama", "PAN", 2},
		{"Costa Rica", "CRI", 2},
		{"Guatemala", "GTM", 6},
		{"Honduras", "HND", 6},
		{"El Salvador", "SLV", 6},
		{"Nicaragua", "NIC", 8},
		{"Cuba", "CUB", 10},
		{"Venezuela", "VEN", 10},
	}
)

type Currency struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Symbol string `json:"symbol"`
}

type DSTInfo struct {
	UTCTime        string `json:"utc_time"`
	Duration       string `json:"duration"`
	Gap            bool   `json:"gap"`
	DateTimeAfter  string `json:"dateTimeAfter"`
	DateTimeBefore string `json:"dateTimeBefore"`
	Overlap        bool   `json:"overlap"`
}

type TimeZone struct {
	Name            string  `json:"name"`
	Offset          int     `json:"offset"`
	OffsetWithDST   int     `json:"offset_with_dst"`
	CurrentTime     string  `json:"current_time"`
	CurrentTimeUnix float64 `json:"current_time_unix"`
	IsDST           bool    `json:"is_dst"`
	DSTSavings      int     `json:"dst_savings"`
	DSTExists       bool    `json:"dst_exists"`
	DSTStart        DSTInfo `json:"dst_start"`
	DSTEnd          DSTInfo `json:"dst_end"`
}

type IPGeolocation struct {
	IP                  string   `json:"ip"`
	ContinentCode       string   `json:"continent_code"`
	ContinentName       string   `json:"continent_name"`
	CountryCode2        string   `json:"country_code2"`
	CountryCode3        string   `json:"country_code3"`
	CountryName         string   `json:"country_name"`
	CountryNameOfficial string   `json:"country_name_official"`
	CountryCapital      string   `json:"country_capital"`
	StateProv           string   `json:"state_prov"`
	StateCode           string   `json:"state_code"`
	District            string   `json:"district"`
	City                string   `json:"city"`
	Zipcode             string   `json:"zipcode"`
	Latitude            string   `json:"latitude"`
	Longitude           string   `json:"longitude"`
	IsEU                bool     `json:"is_eu"`
	CallingCode         string   `json:"calling_code"`
	CountryTLD          string   `json:"country_tld"`
	Languages           string   `json:"languages"`
	CountryFlag         string   `json:"country_flag"`
	GeonameID           string   `json:"geoname_id"`
	ISP                 string   `json:"isp"`
	ConnectionType      string   `json:"connection_type"`
	Organization        string   `json:"organization"`
	CountryEmoji        string   `json:"country_emoji"`
	Currency            Currency `json:"currency"`
	TimeZone            TimeZone `json:"time_zone"`
}

func getAPIKey(filepath string) (string, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return "", nil
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	return trimmed, nil
}

func getIPGeolocation(apiKey string, ip string) (string, error) {
	url := fmt.Sprintf("https://api.ipgeolocation.io/ipgeo?apiKey=%s&ip=%s", apiKey, ip)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func isPrivateIP(ipStr string) bool {
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range privateCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

func QueryOnline(apiKey, ip string) (*IPGeolocation, error) {

	if isPrivateIP(ip) {
		return nil, nil
	}

	filename := fmt.Sprintf("%s.json", ip)

	var jsonData []byte

	// use caching so we dont do recursive lookups
	_, err := os.Stat(filename)
	if err == nil {
		log.Infof("Cached: %s\n", filename)
		jsonFile, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer jsonFile.Close()

		jsonRaw, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			return nil, err
		}

		jsontmp, err := strconv.Unquote(string(jsonRaw))
		if err != nil {
			return nil, err
		}

		jsonData = []byte(jsontmp)
	} else {
		log.Infof("Searched: %s\n", ip)
		// query online
		geoData, err := getIPGeolocation(apiKey, ip)
		if err != nil {
			return nil, err
		}

		// write results to file
		jsonData, err = json.MarshalIndent(geoData, "", " ")
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(filename, jsonData, 0644)
		if err != nil {
			return nil, err
		}

		jsontmp, err := strconv.Unquote(string(jsonData))
		if err != nil {
			return nil, err
		}

		jsonData = []byte(jsontmp)
	}

	// private ip
	if strings.Contains(string(jsonData), "doesn't exist") {
		return nil, nil
	}

	log.Infof("unmarshalling: %s\n", ip)
	var geoData IPGeolocation
	err = json.Unmarshal([]byte(jsonData), &geoData)
	if err != nil {
		log.Errorf("data: %s", jsonData)
		return nil, err
	}

	return &geoData, nil
}

func randID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(65536) + 1
}

func threat() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(10)
}

func threatLow() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(3)
}

func threatHigh() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(3) + 4
}

func Convert(apiKey string, ips []string) (*pathfinder.Response, error) {
	if len(ips) < 2 {
		return nil, fmt.Errorf("need 2 or more ips for a path")
	}

	out := &pathfinder.Response{
		TotalCount: 1,
		PageSize:   500,
		Page:       1,
		Errors:     nil,
		Data: []pathfinder.Data{
			pathfinder.Data{
				ID:   randID(),        // random
				Src:  ips[0],          //
				Dst:  ips[len(ips)-1], //
				Hops: []pathfinder.Hop{},
				//Finished: true,
				Errors: nil,
			},
		},
	}

	for c, ip := range ips {
		geoData, err := QueryOnline(apiKey, ip)
		if err != nil {
			return nil, err
		}

		hop := pathfinder.Hop{
			IP:       ip,
			ProbeTTL: c,
			Hostname: "",
		}

		// private
		if geoData == nil {
			hop.Threat = 0
			hop.Reserved = pathfinder.Reserved{Name: "Private network"}
		} else {
			threat := threatLow()
			for _, country := range countries {
				if geoData.CountryCode3 == country.Code {
					threat = country.Threat
				}
			}
			x := pathfinder.ASN{
				Name: geoData.ISP,
				Country: pathfinder.Country{
					Name:   geoData.CountryName,
					ISO:    geoData.CountryCode3,
					Threat: threat,
				},
				Threat: threat,
			}
			y := pathfinder.Organization{
				Name: geoData.Organization,
			}
			hop.ASN = x
			hop.Organization = y
		}

		out.Data[0].Hops = append(out.Data[0].Hops, hop)
	}

	return out, nil

}
