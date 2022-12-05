package wincred

import (
	"bytes"
	"net/url"
	"strings"
	"errors"

	winc "github.com/danieljoos/wincred"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/registryurl"

	"net/http"
	"encoding/json"
	"io/ioutil"
	"os"
)

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	IdToken string `json:"id_token"`
	ExpiresIn int `json:"expires_in"`
	TokenType string `json:"token_type"`
}

// Wincred handles secrets using the Windows credential service.
type Wincred struct{}

// Add adds new credentials to the windows credentials manager.
func (h Wincred) Add(creds *credentials.Credentials) error {
	credsLabels := []byte(credentials.CredsLabel)
	g := winc.NewGenericCredential(creds.ServerURL)
	g.UserName = creds.Username
	g.CredentialBlob = []byte(creds.Secret)
	g.Persist = winc.PersistLocalMachine
	g.Attributes = []winc.CredentialAttribute{{Keyword: "label", Value: credsLabels}}

	return g.Write()
}

// Delete removes credentials from the windows credentials manager.
func (h Wincred) Delete(serverURL string) error {
	g, err := winc.GetGenericCredential(serverURL)
	if g == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return g.Delete()
}

// Modify GET function for windows
// Get retrieves credentials from the windows credentials manager.
func (h Wincred) Get(serverURL string) (string, string, error) {
	clientId, okClientId := os.LookupEnv("CLIENT_ID")

	if !okClientId {
		return "", "", errors.New("env variable CLIENT_ID is not found")
	}

	clientSecret, okClientSecret := os.LookupEnv("CLIENT_SECRET")

	if !okClientSecret {
		return "", "", errors.New("env variable CLIENT_SECRET is not found")
	}
	
	auth, err := GetAuthorizationToken(clientId, clientSecret)

	return "muniker", auth.AccessToken, err
}

// Get access token from amazoncognito using client credentials.
func GetAuthorizationToken(clientId string, clientSecret string) (*AuthResponse, error) {	
	var cognitoAuthEndpoint = "https://azad.auth.us-west-2.amazoncognito.com/oauth2/token"

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "client_credentials")
	encodedData := data.Encode()

	response, httpErr := http.Post(cognitoAuthEndpoint, "application/x-www-form-urlencoded", strings.NewReader(encodedData))
	
	if httpErr != nil {
		return nil, httpErr
	}
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body) 

	var authResponse AuthResponse
	
	unmarshalErr := json.Unmarshal(body, &authResponse)
	if unmarshalErr != nil {
		return nil, httpErr
    }

	return &authResponse, nil
}

func getTarget(serverURL string) (string, error) {
	s, err := registryurl.Parse(serverURL)
	if err != nil {
		return serverURL, nil
	}

	creds, err := winc.List()
	if err != nil {
		return "", err
	}

	var targets []string
	for i := range creds {
		attrs := creds[i].Attributes
		for _, attr := range attrs {
			if attr.Keyword == "label" && bytes.Equal(attr.Value, []byte(credentials.CredsLabel)) {
				targets = append(targets, creds[i].TargetName)
			}
		}
	}

	if target, found := findMatch(s, targets, exactMatch); found {
		return target, nil
	}

	if target, found := findMatch(s, targets, approximateMatch); found {
		return target, nil
	}

	return "", nil
}

func findMatch(serverUrl *url.URL, targets []string, matches func(url.URL, url.URL) bool) (string, bool) {
	for _, target := range targets {
		tURL, err := registryurl.Parse(target)
		if err != nil {
			continue
		}
		if matches(*serverUrl, *tURL) {
			return target, true
		}
	}
	return "", false
}

func exactMatch(serverURL, target url.URL) bool {
	return serverURL.String() == target.String()
}

func approximateMatch(serverURL, target url.URL) bool {
	//if scheme is missing assume it is the same as target
	if serverURL.Scheme == "" {
		serverURL.Scheme = target.Scheme
	}
	//if port is missing assume it is the same as target
	if serverURL.Port() == "" && target.Port() != "" {
		serverURL.Host = serverURL.Host + ":" + target.Port()
	}
	//if path is missing assume it is the same as target
	if serverURL.Path == "" {
		serverURL.Path = target.Path
	}
	return serverURL.String() == target.String()
}

// List returns the stored URLs and corresponding usernames for a given credentials label.
func (h Wincred) List() (map[string]string, error) {
	creds, err := winc.List()
	if err != nil {
		return nil, err
	}

	resp := make(map[string]string)
	for i := range creds {
		attrs := creds[i].Attributes
		for _, attr := range attrs {
			if strings.Compare(attr.Keyword, "label") == 0 &&
				bytes.Compare(attr.Value, []byte(credentials.CredsLabel)) == 0 {

				resp[creds[i].TargetName] = creds[i].UserName
			}
		}

	}
	return resp, nil
}
