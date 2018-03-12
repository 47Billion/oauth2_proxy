package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api-server/models"

	"github.com/apex/log"
	"github.com/sethgrid/pester"
)

// Create's access token for google and linkedin POST call
func createGoogleLinkedinToken(endpoint string, reqData models.GoogleLinkedinTokenRequest) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// make request data in url value form
	params := url.Values{}
	params.Add("client_id", reqData.ClientId)
	params.Add("client_secret", reqData.ClientSecret)
	params.Add("redirect_uri", reqData.RedirectUrl)
	params.Add("code", reqData.Code)
	params.Add("grant_type", reqData.GrantType)

	// Request object with POST method
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Response
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if nil != err {
		log.Errorf("createGoogleLinkedinToken() Unable to call token API err=%+v", err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("createGoogleLinkedinToken() Unable to read response err=%+v", err)
		return
	} else if status != 200 {
		log.Errorf("createGoogleLinkedinToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
		err = fmt.Errorf("createGoogleLinkedinToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
	}
	return
}

// Create's access token for google and linkedin POST call
func createGoogleRefreshToken(endpoint string, reqData models.GoogleLinkedinTokenRequest) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	log.Infof("reqData.GrantType - %s", reqData.GrantType)
	// make request data in url value form
	params := url.Values{}
	params.Add("client_id", reqData.ClientId)
	params.Add("client_secret", reqData.ClientSecret)
	params.Add("refresh_token", reqData.RefreshToken)
	params.Add("grant_type", reqData.GrantType)

	log.Info(params.Encode())
	// Request object with POST method
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Response
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if nil != err {
		log.Errorf("createGoogleLinkedinToken() Unable to call token API err=%+v", err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("createGoogleLinkedinToken() Unable to read response err=%+v", err)
		return
	} else if status != 200 {
		log.Errorf("createGoogleLinkedinToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
		err = fmt.Errorf("Something went wrong statusCode=%d, msg=%s", status, string(respData))
	}
	return
}

// Create's access token for github POST call
func createGithubAccessToken(endpoint string, reqData models.GithubTokenRequest) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	data, err := json.Marshal(reqData)
	if nil != err {
		log.Errorf("createGithubAccessToken() Unable to marshal request data err=%+v", err)
		return
	}

	// New Request object
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	// Response
	var resp *http.Response
	resp, err = client.Do(req)
	if nil != err {
		log.Errorf("createGithubAccessToken() Unable to call token API err=%+v", err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("createGithubAccessToken() Unable to read response err=%+v", err)
		return
	} else if status != 200 {
		log.Errorf("createGithubAccessToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
		err = fmt.Errorf("createGithubAccessToken() something went wrong statusCode=%d, msg=%s", status, string(respData))

	}
	return
}

// Common request handler that will handle all get requests. FB gives token with a GET call.
func serverRequest(endpoint, provider string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// Response
	var resp *http.Response
	resp, err = client.Get(endpoint)
	if nil != err {
		log.Errorf("serverRequest() Unable to call %s server for endpoint=%s; err=%+v", provider, endpoint, err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("serverRequest() Unable to read response of endpoint=%s; err=%+v", endpoint, err)
		return
	} else if status != 200 {
		log.Errorf("serverRequest() something went wrong endpoint=%s, statusCode=%d, msg=%s", endpoint, status, string(respData))
		err = fmt.Errorf("Something went wrong endpoint=%s, statusCode=%d, msg=%s", endpoint, status, string(respData))
	}
	return
}

func getLinkedinUserInfo(endpoint, token string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// New GET Request and setting auth header.
	req, err := http.NewRequest("GET", endpoint, nil)
	authHeaderVal := fmt.Sprintf("Bearer %s", token)
	req.Header.Set("Authorization", authHeaderVal)

	// Response
	var resp *http.Response
	resp, err = client.Do(req)
	if nil != err {
		log.Errorf("getLinkedinUserInfo() Unable to call Linkedin server for endpoint=%s; err=%+v", endpoint, err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("getLinkedinUserInfo() Unable to read response of endpoint=%s; err=%+v", endpoint, err)
		return
	} else if status != 200 {
		log.Errorf("getLinkedinUserInfo() something went wrong endpoint=%s, statusCode=%d, msg=%s", endpoint, status, string(respData))
		err = fmt.Errorf("Something went wrong endpoint=%s, statusCode=%d, msg=%s", endpoint, status, string(respData))
	}
	return
}
