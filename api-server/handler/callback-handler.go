package handler

import (
	"fmt"
	"net/http"
	"strings"
	"encoding/json"
	"strconv"

	"github.com/47Billion/oauth2_proxy/api-server/models"

	"github.com/gin-gonic/gin"
	"github.com/apex/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/47Billion/oauth2_proxy/config"
)

const (
	// Google Client config
	GoogleTokenUrl = "https://www.googleapis.com/oauth2/v3/token"
	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="
	GoogleGrantType = "authorization_code"

	// FB Client config
	FBAccessTokenUrl = "https://graph.facebook.com/v2.12/oauth/access_token"
	FBGetUserUrl = "https://graph.facebook.com/v2.12/me?access_token="

	// Github Client config
	GithubTokenUrl = "https://github.com/login/oauth/access_token"
	GithubUserUrl = "https://api.github.com/user"
)

// Process oauth2 callback request for google, this will generate new access token and get user details.
func Google(c *gin.Context) {
	var tokenResponse models.GoogleTokenResp
	var userInfo models.GoogleUserInfo
	var err error
	var code = c.Query("code")

	// Create new token request data
	googleConfig := config.Oauth2Config["google"]
	fmt.Println("Google ClientId :- ", googleConfig["client_id"].(string))
	tokenReq := models.GoogleTokenRequest{
		Code:code,
		ClientId:googleConfig["client_id"].(string),
		ClientSecret: googleConfig["client_secret"].(string),
		RedirectUrl: googleConfig["redirect_url"].(string),
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
	redirectResponse := models.RedirectResponse{
		Id:userInfo.Id,
		Name:userInfo.Name,
		Email:userInfo.Email,
		Link:userInfo.Link,
		Picture:userInfo.Picture,
		Gender:userInfo.Gender,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Google() Unable to create JWT token; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	err = callbackRequest(config.CallbackUrl, tokenString)
	if nil != err {
		log.Errorf("Google() Unable to send JWT token at redirectURL; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!", "token": tokenString})
}

// Process oauth2 callback request for facebook, this will generate new access token and get user details.
func Facebook(c *gin.Context) {
	var fbToken models.FBTokenResp
	var userInfo models.FBUserInfo
	var err error
	var code = c.Query("code")

	// Generate access token
	fbConfig := config.Oauth2Config["fb"]
	clientId := fbConfig["client_id"].(string)
	redirectUrl := fbConfig["redirect_url"].(string)
	clientSecret := fbConfig["client_secret"].(string)
	endpoint := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s", FBAccessTokenUrl, clientId, redirectUrl, clientSecret, code)
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
	redirectResponse := models.RedirectResponse{
		Id: userInfo.Id,
		Name:userInfo.Name,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Facebook() Unable to create JWT token; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	err = callbackRequest(config.CallbackUrl, tokenString)
	if nil != err {
		log.Errorf("Facebook() Unable to send JWT token at redirectURL; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!", "token": tokenString})
}

// Process oauth2 callback request for github, this will generate new access token and get user details.
func Github(c *gin.Context) {
	var gitUserInfo models.GitUserInfo
	var err error
	var code = c.Query("code")
	var state = c.Query("state")

	// New request token data
	githubConfig := config.Oauth2Config["github"]
	token := models.GithubTokenRequest{
		ClientId: githubConfig["client_id"].(string),
		ClientSecret: githubConfig["client_secret"].(string),
		RedirectUrl: githubConfig["redirect_url"].(string),
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

	// TODO: Need to check how we'll get response in json format.
	// Create new user info url to fetch details using access token
	respList := strings.Split(string(respData), "&")
	endpoint := fmt.Sprintf("%s?%s", GithubUserUrl, respList[0]) // splitting the response and using access token here.
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

	log.Infof("User Details: %+v", gitUserInfo)
	id := strconv.FormatInt(gitUserInfo.Id, 10)
	redirectResponse := models.RedirectResponse{
		Id:id,
		Name:gitUserInfo.Name,
		Email:gitUserInfo.Email,
		Link:gitUserInfo.HtmlUrl,
		Picture:gitUserInfo.AvatarUrl,
	}
	err, tokenString := createJWTToken(redirectResponse)
	if nil != err {
		log.Errorf("Github() Unable to create JWT token; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	err = callbackRequest(config.CallbackUrl, tokenString)
	if nil != err {
		log.Errorf("Github() Unable to send JWT token at redirectURL; err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "All Ok!!!", "token": tokenString})
}

func createJWTToken(data interface{}) (err error, tokenString string) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"data":data})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err = token.SignedString([]byte("47BOauth2Proxy"))
	if nil != err {
		log.Errorf("createJWTToken() Unable to create JWT token; err=%+v", err)
		return
	}
	fmt.Println(tokenString, err)
	return
}