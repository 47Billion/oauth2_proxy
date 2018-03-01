package models

import "time"

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type GithubTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUrl  string `json:"redirect_url"`
	Code         string `json:"code"`
	State        string `json:"state"`
}

type GithubTokenResp struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type FBTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64 `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type GoogleTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUrl  string `json:"redirect_url"`
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
}

type GoogleTokenResp struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64 `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

type RedirectResponse struct {
	Id      string `json:"id"`
	Email   string `json:"e"`
	Name    string `json:"nm"`
	Link    string `json:"l"`
	Gender  string `json:"g"`
	Picture string `json:"p"`
}

type GoogleUserInfo struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
	Gender        string `json:"gender"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"`
	VerifiedEmail bool   `json:"verified_email"`
}

type FBUserInfo struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type GitUserInfo struct {
	Id               int64 `json:"id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	SiteAdmin        bool `json:"site_admin"`
	FollowingUrl     string `json:"following_url"`
	EventsUrl        string `json:"events_url"`
	HtmlUrl          string `json:"html_url"`
	ReveivedEvensUrl string `json:"reveived_evens_url"`
	Hireable         string `json:"hireable"`
	PublicRepos      int `json:"public_repos"`
	Followers        int `json:"followers"`
	AvatarUrl        string `json:"avatar_url"`
	GravatarId       string `json:"gravatar_id"`
	Company          string `json:"company"`
	Bio              string `json:"bio"`
	ReposUrl         string `json:"repos_url"`
	CreatedAt        time.Time `json:"created_at"`
	Url              string `json:"url"`
	Blog             string `json:"blog"`
	UpdatedAt        time.Time `json:"updated_at"`
	FollowersUrl     string `json:"followers_url"`
	Following        int `json:"following"`
	Location         string `json:"location"`
	StarredUrl       string `json:"starred_url"`
	Login            string `json:"login"`
	GistsUrl         string `json:"gists_url"`
}