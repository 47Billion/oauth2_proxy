package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bitly/oauth2_proxy/api-server/models"
	"github.com/bitly/oauth2_proxy/config"

	"github.com/apex/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/kataras/iris/core/errors"
)

const (
	// Google Urls
	GoogleTokenUrl    = "https://www.googleapis.com/oauth2/v3/token"
	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="
	GoogleGrantType   = "authorization_code"

	// FB Urls
	FBAccessTokenUrl = "https://graph.facebook.com/v2.12/oauth/access_token"
	FBGetUserUrl     = "https://graph.facebook.com/v2.12/me?access_token="

	// Github Urls
	GithubTokenUrl = "https://github.com/login/oauth/access_token"
	GithubUserUrl  = "https://api.github.com/user"

	// Linkedin Urls
	LinkedinTokenUrl    = "https://www.linkedin.com/oauth/v2/accessToken"
	LinkedinUserInfoUrl = "https://api.linkedin.com/v1/people/~?format=json"
)

// Process oauth2 callback request for google, this will generate new access token and get user details.
func Google(rw http.ResponseWriter, req *http.Request) {
	var tokenResponse models.GoogleTokenResp
	var userInfo models.GoogleUserInfo
	var err error
	var url string
	var code = req.URL.Query().Get("code")

	// Create new token request data
	googleConfig := config.Oauth2Config["google"]
	tokenReq := models.GoogleLinkedinTokenRequest{
		Code:         code,
		ClientId:     googleConfig["client_id"].(string),
		ClientSecret: googleConfig["client_secret"].(string),
		RedirectUrl:  googleConfig["redirect_url"].(string),
		GrantType:    GoogleGrantType,
	}

	// Create new access token
	err, respData := createGoogleLinkedinToken(GoogleTokenUrl, tokenReq)
	if nil != err {
		log.Errorf("Google() Unable to generate token for Google with code=%s; err=%+v", code, err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Unmarshal token response data
	err = json.Unmarshal(respData, &tokenResponse)
	if nil != err {
		log.Errorf("Google() Unable to unmarshal token response data err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Create proper user info api with access token
	userInfoEndpoint := fmt.Sprintf("%s%s", GoogleUserInfoUrl, tokenResponse.AccessToken)

	// Get user details using access token
	err, userInfoBytes := serverRequest(userInfoEndpoint, "Google")
	if nil != err {
		log.Errorf("Google() Unable to fetch user details; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Unmarshal token response data
	err = json.Unmarshal(userInfoBytes, &userInfo)
	if nil != err {
		log.Errorf("Google() Unable to unmarshal user info data; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	redirectResponse := models.RedirectResponse{
		Id:      userInfo.Id,
		Name:    userInfo.Name,
		Email:   userInfo.Email,
		Link:    userInfo.Link,
		Picture: userInfo.Picture,
		Gender:  userInfo.Gender,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Google() Unable to create JWT token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	url = fmt.Sprintf("%s?token=%s", config.CallbackUrl, tokenString)
	http.Redirect(rw, req, url, http.StatusPermanentRedirect)
	log.Infof("Google() Permanently redirected the token to callbackurl=%s", config.CallbackUrl)
}

// Process oauth2 callback request for facebook, this will generate new access token and get user details.
func Facebook(rw http.ResponseWriter, req *http.Request) {
	var fbToken models.FBTokenResp
	var userInfo models.FBUserInfo
	var err error
	var url string
	var code = req.URL.Query().Get("code")

	// Generate access token
	fbConfig := config.Oauth2Config["fb"]
	clientId := fbConfig["client_id"].(string)
	redirectUrl := fbConfig["redirect_url"].(string)
	clientSecret := fbConfig["client_secret"].(string)
	endpoint := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s", FBAccessTokenUrl, clientId, redirectUrl, clientSecret, code)
	err, respData := serverRequest(endpoint, "Facebook")
	if nil != err {
		log.Errorf("Facebook() Unable to generate token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	err = json.Unmarshal(respData, &fbToken)
	if nil != err {
		log.Errorf("Facebook() Unable to unmarshal response data err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Use access token to get user name and user_id
	userInfoUrl := fmt.Sprintf("%s%s", FBGetUserUrl, fbToken.AccessToken)
	err, userInfoBytes := serverRequest(userInfoUrl, "Facebook")
	if nil != err {
		log.Errorf("Facebook() Unable to fetch user details; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Unmarshal token response data
	err = json.Unmarshal(userInfoBytes, &userInfo)
	if nil != err {
		log.Errorf("Facebook() Unable to unmarshal user info data; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	redirectResponse := models.RedirectResponse{
		Id:   userInfo.Id,
		Name: userInfo.Name,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Facebook() Unable to create JWT token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	url = fmt.Sprintf("%s?token=%s", config.CallbackUrl, tokenString)
	http.Redirect(rw, req, url, http.StatusPermanentRedirect)
	log.Infof("Facebook() Permanently redirected the token to callbackurl=%s", config.CallbackUrl)
}

// Process oauth2 callback request for github, this will generate new access token and get user details.
func Github(rw http.ResponseWriter, req *http.Request) {
	var gitUserInfo models.GitUserInfo
	var err error
	var url string
	var code = req.URL.Query().Get("code")
	var state = req.URL.Query().Get("state")

	// New request token data
	githubConfig := config.Oauth2Config["github"]
	token := models.GithubTokenRequest{
		ClientId:     githubConfig["client_id"].(string),
		ClientSecret: githubConfig["client_secret"].(string),
		RedirectUrl:  githubConfig["redirect_url"].(string),
		Code:         code,
		State:        state,
	}

	// Create new access token
	err, respData := createGithubAccessToken(GithubTokenUrl, token)
	if nil != err {
		log.Errorf("Github() Unable to generate access token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// TODO: Need to check how we'll get response in json format.
	// Create new user info url to fetch details using access token
	respList := strings.Split(string(respData), "&")
	endpoint := fmt.Sprintf("%s?%s", GithubUserUrl, respList[0]) // splitting the response and using access token here.
	err, resp := serverRequest(endpoint, "Github")
	if nil != err {
		log.Errorf("Github() Unable to fetch user details; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	err = json.Unmarshal(resp, &gitUserInfo)
	if nil != err {
		log.Errorf("Github() Unable to unmarshal user info data; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	id := strconv.FormatInt(gitUserInfo.Id, 10) // TODO: getting id in int format, need to convert it or not?
	redirectResponse := models.RedirectResponse{
		Id:      id,
		Name:    gitUserInfo.Name,
		Email:   gitUserInfo.Email,
		Link:    gitUserInfo.HtmlUrl,
		Picture: gitUserInfo.AvatarUrl,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Github() Unable to create JWT token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	url = fmt.Sprintf("%s?token=%s", config.CallbackUrl, tokenString)
	http.Redirect(rw, req, url, http.StatusPermanentRedirect)
	log.Infof("Github() Permanently redirected the token to callbackurl=%s", config.CallbackUrl)
}

// Process oauth2 callback request for github, this will generate new access token and get user details.
func Linkedin(rw http.ResponseWriter, req *http.Request) {
	var tokenResponse models.LinkedinTokenResp
	var userInfo models.LinkedinUserInfo
	var err error
	var url string
	var code = req.URL.Query().Get("code")

	// New access token request data
	linkedinConfig := config.Oauth2Config["linkedin"]
	token := models.GoogleLinkedinTokenRequest{
		ClientId:     linkedinConfig["client_id"].(string),
		ClientSecret: linkedinConfig["client_secret"].(string),
		RedirectUrl:  linkedinConfig["redirect_url"].(string),
		Code:         code,
		GrantType:    "authorization_code",
	}

	// Create new access token
	err, respData := createGoogleLinkedinToken(LinkedinTokenUrl, token)
	if nil != err {
		log.Errorf("Linkedin() Unable to generate token for Google with code=%s; err=%+v", code, err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Unmarshal token response data
	err = json.Unmarshal(respData, &tokenResponse)
	if nil != err {
		log.Errorf("Linkedin() Unable to unmarshal token response data err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	// Get user details using access token
	err, userResp := getLinkedinUserInfo(LinkedinUserInfoUrl, tokenResponse.AccessToken)
	if nil != err {
		log.Errorf("Linkedin() Unable to fetch user details; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	err = json.Unmarshal(userResp, &userInfo)
	if nil != err {
		log.Errorf("Linkedin() Unable to unmarshal user info data; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}

	log.Infof("User Details: %+v", userInfo)
	name := fmt.Sprintf("%s %s", userInfo.FirstName, userInfo.LastName)
	redirectResponse := models.RedirectResponse{
		Id:   userInfo.Id,
		Name: name,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Linkedin() Unable to create JWT token; err=%+v", err)
		url = fmt.Sprintf("%s?error=error", config.CallbackUrl)
		http.Redirect(rw, req, config.CallbackUrl, http.StatusPermanentRedirect)
		return
	}
	url = fmt.Sprintf("%s?token=%s", config.CallbackUrl, tokenString)
	http.Redirect(rw, req, url, http.StatusPermanentRedirect)
	log.Infof("Linkedin() Permanently redirected the token to callbackurl=%s", config.CallbackUrl)
}

func createJWTToken(data interface{}) (err error, tokenString string) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"data": data})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err = token.SignedString([]byte("47BOauth2Proxy"))
	if nil != err {
		log.Errorf("createJWTToken() Unable to create JWT token; err=%+v", err)
		return
	}
	err = errors.New("Error while creating token")
	return
}
