package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bitly/oauth2_proxy/api-server/handler"
	"github.com/bitly/oauth2_proxy/config"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
)

type AbstractProxy struct {
	oauthProxy map[string]*OAuthProxy
	serveMux   http.Handler
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	flagSet := flag.NewFlagSet("oauth2_proxy", flag.ExitOnError)

	emailDomains := StringArray{}
	upstreams := StringArray{}
	skipAuthRegex := StringArray{}
	googleGroups := StringArray{}

	//config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Var(&skipAuthRegex, "skip-auth-regex", "bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS")

	flagSet.Var(&emailDomains, "email-domain", "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.String("azure-tenant", "common", "go to a tenant-specific or common (tenant-independent) endpoint.")
	flagSet.String("github-org", "", "restrict logins to members of this organisation")
	flagSet.String("github-team", "", "restrict logins to members of this team")
	flagSet.Var(&googleGroups, "google-group", "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("google-admin-email", "", "the google admin to impersonate for api calls")
	flagSet.String("google-service-account-json", "", "the path to the service account json credentials")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
	flagSet.Duration("cookie-expire", time.Duration(168) * time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")

	flagSet.Bool("request-logging", true, "Log requests to stdout")
	flagSet.String("request-logging-format", defaultRequestLoggingFormat, "Template for log lines")

	flagSet.String("provider", "google", "OAuth provider")
	flagSet.String("oidc-issuer-url", "", "OpenID Connect issuer URL (ie: https://accounts.google.com)")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("resource", "", "The resource that is protected (Azure AD only)")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")

	// Added by Ankit
	google := flagSet.Bool("google", true, "Provides Oauth2 service for google")
	fb := flagSet.Bool("fb", false, "Provides Oauth2 service for facebook")
	git := flagSet.Bool("github", false, "Provides Oauth2 service for github")
	linkedin := flagSet.Bool("linkedin", false, "Provides Oauth2 service for linkedin")
	callbackUrl := flagSet.String("callback-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	customLoginPage := flagSet.String("login-page", "", "path to custom login html template")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2_proxy v%s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	if *callbackUrl == "" {
		fmt.Printf("Invalid configuration:\n%s\n", "missing setting: callback-url")
		os.Exit(0)

	} else {
		config.CallbackUrl = *callbackUrl
	}
	if *customLoginPage == "" {
		fmt.Printf("Invalid configuration:\n%s\n", "missing setting: custom-login-template")
		os.Exit(0)
	} else {
		config.SigninTemplate = *customLoginPage
	}

	opts := NewOptions()
	var googleOAuthproxy, fbOAuthproxy, githubOAuthproxy, linkedinOAuthproxy *OAuthProxy

	if *google {
		googleOpts := NewOptions()
		googleCfg := make(EnvOptions)
		googleCfg = loadOptionsFromConfig("config/google.cfg", googleCfg)
		googleCfg["redirect_url"] = fmt.Sprintf("%s%s/callback", googleCfg["base_url"], googleCfg["proxy-prefix"])
		config.Oauth2Config["google"] = googleCfg
		googleOAuthproxy = verifyOpts(googleOpts, flagSet, googleCfg)
	}
	if *fb {
		fbOpts := NewOptions()
		fbCfg := make(EnvOptions)
		fbCfg = loadOptionsFromConfig("config/fb.cfg", fbCfg)
		fbCfg["redirect_url"] = fmt.Sprintf("%s%s/callback", fbCfg["base_url"], fbCfg["proxy-prefix"])
		config.Oauth2Config["fb"] = fbCfg
		fbOAuthproxy = verifyOpts(fbOpts, flagSet, fbCfg)
	}
	if *git {
		gitOpts := NewOptions()
		gitCfg := make(EnvOptions)
		gitCfg = loadOptionsFromConfig("config/github.cfg", gitCfg)
		gitCfg["redirect_url"] = fmt.Sprintf("%s%s/callback", gitCfg["base_url"], gitCfg["proxy-prefix"])
		config.Oauth2Config["github"] = gitCfg
		githubOAuthproxy = verifyOpts(gitOpts, flagSet, gitCfg)
	}
	if *linkedin {
		linkedinOpts := NewOptions()
		linkedinCfg := make(EnvOptions)
		linkedinCfg = loadOptionsFromConfig("config/linkedin.cfg", linkedinCfg)
		linkedinCfg["redirect_url"] = fmt.Sprintf("%s%s/callback", linkedinCfg["base_url"], linkedinCfg["proxy-prefix"])
		config.Oauth2Config["linkedin"] = linkedinCfg
		linkedinOAuthproxy = verifyOpts(linkedinOpts, flagSet, linkedinCfg)
	}

	serveMux := http.NewServeMux()
	abstractProxy := &AbstractProxy{
		oauthProxy: map[string]*OAuthProxy{
			"google":   googleOAuthproxy,
			"fb":       fbOAuthproxy,
			"github":   githubOAuthproxy,
			"linkedin": linkedinOAuthproxy,
		},
		serveMux: serveMux,
	}

	s := &Server{
		Handler: LoggingHandler(os.Stdout, abstractProxy, opts.RequestLogging, opts.RequestLoggingFormat),
		Opts:    opts,
	}
	s.ListenAndServe()
}

func (a *AbstractProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	pathString := req.URL.Path
	var p *OAuthProxy
	if strings.HasPrefix(pathString, "/google") {
		p = a.oauthProxy["google"]
	} else if strings.HasPrefix(pathString, "/fb") {
		p = a.oauthProxy["fb"]
	} else if strings.HasPrefix(pathString, "/github") {
		p = a.oauthProxy["github"]
	} else if strings.HasPrefix(pathString, "/linkedin") {
		p = a.oauthProxy["linkedin"]
	}

	if p == nil && req.URL.Path != "/login" {
		rw.WriteHeader(404)
		rw.Write([]byte("404 Something went wrong - " + http.StatusText(404)))
		return
	}

	switch path := req.URL.Path; {
	case path == "/login":
		data, err := ioutil.ReadFile(config.SigninTemplate)
		if nil == err {
			rw.Write(data)
		} else {
			rw.WriteHeader(404)
			rw.Write([]byte("404 Something went wrong - " + http.StatusText(404)))
		}
	case path == "/google/oauth2/callback":
		handler.Google(rw, req) // handle Google callback request
	case path == "/fb/oauth2/callback":
		handler.Facebook(rw, req) // handle Facebook callback request
	case path == "/github/oauth2/callback":
		handler.Github(rw, req) // handle Github callback request
	case path == "/linkedin/oauth2/callback":
		handler.Linkedin(rw, req) // handle Linkedin callback request
	case path == p.RobotsPath:
		p.RobotsTxt(rw)
	case path == p.PingPath:
		p.PingPage(rw)
	case p.IsWhitelistedRequest(req):
		p.serveMux.ServeHTTP(rw, req)
	case path == p.SignInPath:
		p.SignIn(rw, req)
	case path == p.SignOutPath:
		p.SignOut(rw, req)
	case path == p.OAuthStartPath:
		p.OAuthStart(rw, req)
	case path == p.OAuthCallbackPath:
		p.OAuthCallback(rw, req)
	case path == p.AuthOnlyPath:
		p.AuthenticateOnly(rw, req)
	default:
		p.Proxy(rw, req)
	}
}

func verifyOpts(opts *Options, flagSet *flag.FlagSet, cfg map[string]interface{}) *OAuthProxy {
	options.Resolve(opts, flagSet, cfg)

	err := opts.Validate()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy := NewOAuthProxy(opts, validator)

	if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		log.Printf("using htpasswd file %s", opts.HtpasswdFile)
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		oauthproxy.DisplayHtpasswdForm = opts.DisplayHtpasswdForm
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}
	return oauthproxy
}

func loadOptionsFromConfig(configFor string, cfg map[string]interface{}) map[string]interface{} {
	if configFor != "" {
		_, err := toml.DecodeFile(configFor, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", configFor, err)
		}
	}
	return cfg
}
