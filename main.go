package main

/**
References:

* Golang OAuth2 library
	https://github.com/golang/oauth2

* Unity CLI - OAuth2 endpoint
	http://www.unity-idm.eu/documentation/unity-1.9.6/manual.html#endp-oauth-as

* Getting started with OAuth2 in Go
	https://jacobmartins.com/2016/02/29/getting-started-with-oauth2-in-go/
* The Black Magic of Oauth in Golang
	https://medium.com/@hfogelberg/the-black-magic-of-oauth-in-golang-part-1-3cef05c28dde
* Simple Golang HTTP Request Context Example
	https://gocodecloud.com/blog/2016/11/15/simple-golang-http-request-context-example/
* Revisiting context and http.Handler for Go 1.7
	https://www.joeshaw.org/revisiting-context-and-http-handler-for-go-17/



OAuth translation profile:

Name:oauth2
Description:
Rules:

1: Condition:true
Action:createAttribute
Action parameters:attributeName = urn:oid:2.16.840.1.113730.3.1.241
expression = attr['clarin-full-name']
mandatory = false
attributeDisplayName = Name
attributeDescription = Clarin full name

2: Condition:true
Action:createAttribute
Action parameters:attributeName = urn:oid:1.3.6.1.4.1.5923.1.1.1.6
expression = idsByType['email'][0].replaceAll('@', '_') + '@clarin.eu'
mandatory = false
attributeDisplayName =
attributeDescription =

3: Condition:groups contains '/clarin/academic'
Action:createAttribute
Action parameters:attributeName = urn:oid:1.3.6.1.4.1.5923.1.1.1.7
expression = 'http://www.clarin.eu/entitlement/academic'
mandatory = false
attributeDisplayName =
attributeDescription =

4: Condition:groups contains '/clarin/normal'
Action:createAttribute
Action parameters:attributeName = urn:oid:1.3.6.1.4.1.5923.1.1.1.7
expression = 'http://www.clarin.eu/entitlement/none'
mandatory = false
attributeDisplayName =
attributeDescription =

5: Condition:true
Action:createAttribute
Action parameters:attributeName = urn:oid:2.5.4.3
expression = idsByType['email'][0]
mandatory = false
attributeDisplayName =
attributeDescription =


 */
import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"github.com/dchest/uniuri"
	"os"
	"golang.org/x/net/context"
	"io/ioutil"
)

const htmlIndex = `<html><body>
<h3>CLARIN AAI Delegation pilot OAuth 2 test client</h3>
<a href="/login">Log in</a>
</body></html>
`

type Config struct {
	oauth oauth2.Config
	tokenValidationURL string
	userInfoURL string
}

var cfg = Config {
	oauth: oauth2.Config{
		ClientID:     "test",
		ClientSecret: "Abcdefghij",
		RedirectURL:  "http://localhost:3000/callback",
		Scopes:       []string{"user_profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://pilot1.idm.clarin.eu/oauth2-as/oauth2-authz",
			TokenURL: "https://pilot1.idm.clarin.eu/oauth2/token",
		},
	},
	tokenValidationURL: "https://pilot1.idm.clarin.eu/oauth2/tokeninfo",
	userInfoURL: "https://pilot1.idm.clarin.eu/oauth2/userinfo",
}

var ctx = context.Background()

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/callback", callbackHandler)
	server_url := ":3000"
	fmt.Printf("Starting server on url: %s\n", server_url)
	http.ListenAndServe(server_url, router)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, htmlIndex)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	oauthStateString := uniuri.New()
	fmt.Printf("Generated state=%s\n", oauthStateString)
	url := cfg.oauth.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")

	fmt.Printf("state=%s, authz code=%s\n", state, code)
	token, err := cfg.oauth.Exchange(ctx, code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to exchange authorization code for access token.\nError: %s", err)
		fmt.Fprintf(w, "Failed to exchange authorization code into access token.")
		return
	}

	if !token.Valid() {
		fmt.Fprintf(w, "Invalid access token")
		return
	}

	html := ""
	html += fmt.Sprintf("Generated state:            %43s  state=%s\n", "", state)
	html += fmt.Sprintf("Authorization code:         %s, state=%s\n", code, state)
	html += fmt.Sprintf("Exchanged for Access token: %s, state=%s\n", token.AccessToken, state)
	html += fmt.Sprintf("\n")
	html += validateToken(token.AccessToken)
	html += fmt.Sprintf("\n")
	html +=  obtainUserInfo(token.AccessToken)

	fmt.Fprintf(w, "%s", html)
}

func validateToken(token string) (string) {
	url := cfg.tokenValidationURL
	method := "GET"
	req_body := ""

	result := ""
	result += fmt.Sprintf("Token validation:\n")
	result += fmt.Sprintf("  Request:\n")
	result += fmt.Sprintf("    URL: %s\n", url)
	result += fmt.Sprintf("    Method: %s\n", method)
	result += fmt.Sprintf("    Headers: %s=%s\n", "Authorization", fmt.Sprintf("Bearer %s", token))
	result += fmt.Sprintf("    Body: %s\n", req_body)

	req, err := http.NewRequest(method, url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		result += fmt.Sprintf("  Request failed. Error: %s\n", err)
		return result
	}
	defer resp.Body.Close()

	result += fmt.Sprintf("  Response:\n")
	result += fmt.Sprintf("    Status: %s\n", resp.Status)
	result += fmt.Sprintf("    Headers:\n")
	for name, value := range resp.Header {
		result += fmt.Sprintf("    %s=%s\n", name, value)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	result += fmt.Sprintf("    Body:%s\n", string(body))
	return result
}

func obtainUserInfo(token string) (string) {
	url := cfg.userInfoURL
	method := "GET"
	req_body := ""

	result := ""
	result += fmt.Sprintf("User info:\n")
	result += fmt.Sprintf("  Request:\n")
	result += fmt.Sprintf("    URL: %s\n", url)
	result += fmt.Sprintf("    Method: %s\n", method)
	result += fmt.Sprintf("    Headers: %s=%s\n", "Authorization", fmt.Sprintf("Bearer %s", token))
	result += fmt.Sprintf("    Body: %s\n", req_body)

	req, err := http.NewRequest(method, url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
		result += fmt.Sprintf("  Request failed. Error: %s\n", err)
		return result

	}
	defer resp.Body.Close()

	result += fmt.Sprintf("  Response:\n")
	result += fmt.Sprintf("    Status: %s\n", resp.Status)
	result += fmt.Sprintf("    Headers:\n")
	for name, value := range resp.Header {
		result += fmt.Sprintf("    %s=%s\n", name, value)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	result += fmt.Sprintf("    Body: %s\n", string(body))
	return result
}