package handler

import (
	"net/http"
	"encoding/json"
	"net/url"
	"bytes"
	"io/ioutil"

	"github.com/47Billion/oauth2_proxy/api-server/models"

	"github.com/sethgrid/pester"
	"github.com/apex/log"
	"fmt"
)

func createGoogleAccessToken(endpoint string, reqData models.GoogleTokenRequest) (err error, respData []byte) {
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
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	// Response
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if nil != err {
		log.Errorf("createGoogleAccessToken() Unable to call token API err=%+v", err)
		return
	}

	// Read response body data
	status := resp.StatusCode
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("createGoogleAccessToken() Unable to read response err=%+v", err)
		return
	} else if status != 200 {
		log.Errorf("createGoogleAccessToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
		err = fmt.Errorf("createGoogleAccessToken() something went wrong statusCode=%d, msg=%s", status, string(respData))
	}
	return
}

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

	}
	return
}

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
		err = fmt.Errorf("serverRequest() something went wrong endpoint=%s, statusCode=%d, msg=%s", endpoint, status, string(respData))
	}
	return
}

func getGitUser(endpoint string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// Response
	var resp *http.Response
	resp, err = client.Get(endpoint)
	if nil != err {
		log.Errorf("getGitUser() Unable to get user details err=%+v", err)
		return
	}

	// Read response body data
	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("getGitUser() Unable to read response err=%+v", err)
		return
	}
	return
}

func getFBToken(endpoint string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// Response
	var resp *http.Response
	resp, err = client.Get(endpoint)
	if nil != err {
		log.Errorf("getFBToken() Unable to get FB access_token err=%+v", err)
		return
	}

	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("getFBToken() Unable to read FB response err=%+v", err)
		return
	}
	return
}

func inspectFBToken(endpoint string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// Response
	var resp *http.Response
	resp, err = client.Get(endpoint)
	if nil != err {
		log.Errorf("inspectFBToken() Unable to debug FB access_token err=%+v", err)
		return
	}

	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("inspectFBToken() Unable to read FB response err=%+v", err)
		return
	}
	return
}

func getGoogleUserInfo(endpoint string) (err error, respData []byte) {
	// Client
	client := pester.New()
	client.KeepLog = true

	// Response
	var resp *http.Response
	resp, err = client.Get(endpoint)
	if nil != err {
		log.Errorf("inspectFBToken() Unable to debug FB access_token err=%+v", err)
		return
	}

	respData, err = ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Errorf("inspectFBToken() Unable to read FB response err=%+v", err)
		return
	}
	return
}