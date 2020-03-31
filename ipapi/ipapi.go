package ipapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Result struct {
	As          string  `json:"as"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Isp         string  `json:"isp"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Org         string  `json:"org"`
	Query       string  `json:"query"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	TimeZone    string  `json:"timezone"`
	Zip         string  `json:"zip"`
}

const Endpoint = "http://ip-api.com/json"

var EnableQuery bool = true
var ErrQueryDisabled = errors.New("ipapi: Query disabled by user.")
var MockResult *Result = nil

func Query() (*Result, error) {
	if !EnableQuery {
		return nil, ErrQueryDisabled
	}

	if MockResult != nil {
		return MockResult, nil
	}

	resp, err := http.Get(Endpoint)
	if err != nil {
		return nil, fmt.Errorf("http.Get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non 200 response status: %s", resp.Status)
	}

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(resp.Body): %w", err)
	}

	var result Result
	if err := json.Unmarshal(bs, &result); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}
	return &result, nil
}
