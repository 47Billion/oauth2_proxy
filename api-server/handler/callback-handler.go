package handler

import (
	"fmt"
	"net/http"
	"github.com/47Billion/oauth2_proxy/api-server/models"

	"github.com/gin-gonic/gin"
	"github.com/apex/log"
	"strings"
	"encoding/json"
)

const (
	// Redirect URL
	RedirectUrl = "http://sample-test.com:9090/oauth2/callback"

	// Google Client config
	GoogleClientId = "746385050955-tpjjgjev8n34e1v6ldh161r03i0oqmlu.apps.googleusercontent.com"
	GoogleClientSecret = "Faxj657egrO6UttoDcA_qwll"
	GoogleTokenUrl = "https://www.googleapis.com/oauth2/v3/token"
	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="
	GoogleGrantType = "authorization_code"
	GoogleRedirectUrl = "http://sample-test.com:9090/google/oauth2/callback"

	// FB Client config
	FBClientId = "2048964158685583"
	FBClientSecret = "13ba6eca89fc45eff2d848d81cbefc78"
	FBAccessTokenUrl = "https://graph.facebook.com/v2.12/oauth/access_token"
	FBDebugTokenUrl = "https://graph.facebook.com/v2.12/debug_token?input_token"
	FBGetUserUrl = "https://graph.facebook.com/v2.12/me?access_token="
	FBRedirectUrl = "http://sample-test.com:9090/fb/oauth2/callback"

	// Github Client config
	GithubClientId = "dfce3b493e27d84d5288"
	GithubClientSecret = "ce0cb3a3be68dda5bc8dfb8cdcf826c6c3f479fb"
	GithubTokenUrl = "https://github.com/login/oauth/access_token"
	GithubUserUrl = "https://api.github.com/user"
	GithubRedirectUrl = "http://sample-test.com:9090/github/oauth2/callback"
)

/*
func HandleCallback(c *gin.Context) {
	var err error
	var token []byte
	var code = c.Query("code")
	var state = c.Query("state")

	fmt.Println("code length: ", len(code))
	fmt.Println("state length: ", len(state))

	// For Github
	if len(code) == 20 {
		err, token = github(code, state)
	}

	// For FB
	if len(code) == 344 {
		err, token = facebook(code)
	}

	if nil != err {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!", "data": string(token)})
}
*/

// Process oauth2 callback request for google, this will generate new access token and get user details.
func Google(c *gin.Context) {
	var tokenResponse models.GoogleTokenResp
	var userInfo models.GoogleUserInfo
	var err error
	var code = c.Query("code")

	// Create new token request data
	tokenReq := models.GoogleTokenRequest{
		Code:code,
		ClientId:GoogleClientId,
		ClientSecret: GoogleClientSecret,
		RedirectUrl: GoogleRedirectUrl,
		GrantType:  GoogleGrantType,
	}

	// Create new access token
	err, respData := createGoogleAccessToken(GoogleTokenUrl, tokenReq)
	if nil != err {
		log.Errorf("Google() Unable to generate token for Google with code=%s; err=%+v", code, err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	// Unmarshal token response data
	err = json.Unmarshal(respData, &tokenResponse)
	if nil != err {
		log.Errorf("Google() Unable to unmarshal token response data err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	// Create proper user info api with access token
	userInfoEndpoint := fmt.Sprintf("%s%s", GoogleUserInfoUrl, tokenResponse.AccessToken)

	// Get user details using access token
	err, userInfoBytes := serverRequest(userInfoEndpoint, "Google")
	if nil != err {
		log.Errorf("Google() Unable to fetch user details; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	log.Infof("Google User Info : %s", string(userInfoBytes))

	// Unmarshal token response data
	err = json.Unmarshal(userInfoBytes, &userInfo)
	if nil != err {
		log.Errorf("Google() Unable to unmarshal user info data; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!"})
}

// Process oauth2 callback request for facebook, this will generate new access token and get user details.
func Facebook(c *gin.Context) {
	var fbToken models.FBTokenResp
	var userInfo models.FBUserInfo
	var err error
	var code = c.Query("code")

	// Generate access token
	endpoint := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s", FBAccessTokenUrl, FBClientId, FBRedirectUrl, FBClientSecret, code)
	err, respData := serverRequest(endpoint, "Facebook")
	if nil != err {
		log.Errorf("Facebook() Unable to generate token; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	log.Infof("Facebook() response: %s", string(respData))
	err = json.Unmarshal(respData, &fbToken)
	if nil != err {
		log.Errorf("Facebook() Unable to unmarshal response data err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	// Use access token to get user name and user_id
	userInfoUrl := fmt.Sprintf("%s%s", FBGetUserUrl, fbToken.AccessToken)
	log.Infof("Facebook() Debug Token URL: %s", userInfoUrl)
	err, userInfoBytes := serverRequest(userInfoUrl, "Facebook")
	if nil != err {
		log.Errorf("Facebook() Unable to fetch user details; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	log.Infof("Facebook() tokenResp: %s", string(userInfoBytes))

	// Unmarshal token response data
	err = json.Unmarshal(userInfoBytes, &userInfo)
	if nil != err {
		log.Errorf("Facebook() Unable to unmarshal user info data; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!"})
}

// Process oauth2 callback request for github, this will generate new access token and get user details.
func Github(c *gin.Context) {
	var gitUserInfo models.GitUserInfo
	var err error
	var code = c.Query("code")
	var state = c.Query("state")

	githubUser := make(map[string]interface{})

	// New request token data
	token := models.GithubTokenRequest{
		ClientId: GithubClientId,
		ClientSecret: GithubClientSecret,
		RedirectUrl: GithubRedirectUrl,
		Code: code,
		State: state,
	}

	// Create new access token
	err, respData := createGithubAccessToken(GithubTokenUrl, token)
	if nil != err {
		log.Errorf("Github() Unable to generate access token; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	// Create new user info url to fetch details using access token
	respList := strings.Split(string(respData), "&")
	endpoint := fmt.Sprintf("%s?%s", GithubUserUrl, respList[0])
	err, resp := serverRequest(endpoint, "Github")
	if nil != err {
		log.Errorf("Github() Unable to fetch user details; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	err = json.Unmarshal(resp, &gitUserInfo)
	if nil != err {
		log.Errorf("Github() Unable to unmarshal user info data; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	log.Infof("User Details: %+v", githubUser)
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!"})
}