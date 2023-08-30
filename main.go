package gonsx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// struct to hold credentials and NSX configuration
type NSXClient struct {
	Username string
	Password string
	Hostname string
	Client   *http.Client
}

func (nsxConfig *NSXClient) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return req, err
	}

	// add basic auth to request
	req.SetBasicAuth(nsxConfig.Username, nsxConfig.Password)

	return req, err
}

func (nsxConfig *NSXClient) Do(req *http.Request) (*http.Response, error) {
	// send http request
	resp, err := nsxConfig.Client.Do(req)
	if err != nil {
		return nil, err
	}

	backoffRetries := 1

	// check for throttling
	for backoffRetries < 10 && (resp.StatusCode == 429 || resp.StatusCode == 503) {
		fmt.Println("Throttling detected, sleeping a bit and retrying")
		// make sure to close the trashed response
		resp.Body.Close()
		time.Sleep(time.Duration(backoffRetries) * time.Second)
		resp, err = nsxConfig.Client.Do(req)
		if err != nil {
			return nil, err
		}
		backoffRetries++
	}

	// handle unauthorized error
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("HTTP 403: Unauthorized, please verify credentials, and vIDM status")
	}

	return resp, err
}

type searchCursor int

func (s *searchCursor) UnmarshalJSON(data []byte) error {
	var cursorString string
	err := json.Unmarshal(data, &cursorString)
	if err != nil {
		return err
	}

	cursor, err := strconv.Atoi(cursorString)
	if err != nil {
		return err
	}

	*s = searchCursor(cursor)

	return nil
}

func (s searchCursor) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.Itoa(int(s)))
}

type NsxBulkResponse[t NsxApiResource] struct {
	ResultCount   int            `json:"result_count"`
	Results       []t            `json:"results"`
	Links         []ResourceLink `json:"_links"`
	Schema        *string        `json:"_schema"`
	Self          ResourceLink   `json:"_self"`
	Cursor        *searchCursor  `json:"cursor"`
	SortAscending *bool          `json:"sort_ascending"`
	SoryBy        *string        `json:"sort_by"`
}

const (
	SearchPageSize = 1000
	SearchEndpoint = "/policy/api/v1/search"
)

// search for all of a single type, and cursor through the results
func SearchForPageOfType[t NsxApiResource](nsxConfig NSXClient, resourceType string, cursor int) (NsxBulkResponse[t], error) {
	initialRequest := fmt.Sprintf("https://%s%s?query=resource_type:%s&page_size=%d&cursor=%d", nsxConfig.Hostname, SearchEndpoint, resourceType, SearchPageSize, cursor)

	// create http request
	req, err := nsxConfig.NewRequest("GET", initialRequest, nil)
	if err != nil {
		return NsxBulkResponse[t]{}, err
	}

	resp, err := nsxConfig.Do(req)
	if err != nil {
		return NsxBulkResponse[t]{}, err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()

	searchResponse := NsxBulkResponse[t]{}
	err = decoder.Decode(&searchResponse)
	if err != nil {
		return NsxBulkResponse[t]{}, fmt.Errorf("error decoding response: %T %v", searchResponse.Results, err)

	}

	if len(searchResponse.Results) == 0 {
		return NsxBulkResponse[t]{}, fmt.Errorf("no results found for type \"%s\" at cursor location %d", resourceType, cursor)
	}

	return searchResponse, nil
}

// search for a single type, and cursor through the pages to get all results
func SearchForAllOfType[t NsxApiResource](nsxConfig NSXClient, resourceType string) ([]t, error) {
	// get the first page of results
	bulkResponse, err := SearchForPageOfType[t](nsxConfig, resourceType, 0)
	if err != nil {
		return nil, err
	}

	if bulkResponse.Cursor == nil {
		return nil, fmt.Errorf("no cursor found in search response, something is wrong")
	}

	if bulkResponse.ResultCount == int(*bulkResponse.Cursor) {
		return bulkResponse.Results, nil
	}

	results := bulkResponse.Results
	var cursorList []int
	startingCursor := int(*bulkResponse.Cursor)

	for i := startingCursor; i < bulkResponse.ResultCount; i += SearchPageSize {
		cursorList = append(cursorList, i)
	}

	type threadResult struct {
		results []t
		err     error
	}

	resultChannel := make(chan threadResult, len(cursorList))

	for _, cursor := range cursorList {
		go func(cursor int) {
			bulkResponse, err := SearchForPageOfType[t](nsxConfig, resourceType, cursor)
			if err != nil {
				resultChannel <- threadResult{nil, err}
			}
			resultChannel <- threadResult{bulkResponse.Results, nil}
		}(cursor)
	}

	for i := 0; i < len(cursorList); i++ {
		threadResult := <-resultChannel
		if threadResult.err != nil {
			return nil, threadResult.err
		}

		results = append(results, threadResult.results...)
	}

	return results, nil
}
