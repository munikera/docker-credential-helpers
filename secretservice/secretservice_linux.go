package secretservice

/*
#cgo pkg-config: libsecret-1

#include "secretservice_linux.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/docker/docker-credential-helpers/credentials"

	"net/http"
	"net/url"
	"strings"
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

// Secretservice handles secrets using Linux secret-service as a store.
type Secretservice struct{}

// Add adds new credentials to the keychain.
func (h Secretservice) Add(creds *credentials.Credentials) error {
	if creds == nil {
		return errors.New("missing credentials")
	}
	credsLabel := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabel))
	server := C.CString(creds.ServerURL)
	defer C.free(unsafe.Pointer(server))
	username := C.CString(creds.Username)
	defer C.free(unsafe.Pointer(username))
	secret := C.CString(creds.Secret)
	defer C.free(unsafe.Pointer(secret))

	if err := C.add(credsLabel, server, username, secret); err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

// Delete removes credentials from the store.
func (h Secretservice) Delete(serverURL string) error {
	if serverURL == "" {
		return errors.New("missing server url")
	}
	server := C.CString(serverURL)
	defer C.free(unsafe.Pointer(server))

	if err := C.delete(server); err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

// Get returns the username and secret to use for a given registry server URL.
func (h Secretservice) Get(serverURL string) (string, string, error) {
	if serverURL == "" {
		return "", "", errors.New("missing server url")
	}

	clientId, okClientId := os.LookupEnv("CLIENT_ID")

	if !okClientId {
		return "", "", errors.New("env variable CLIENT_ID is not found")
	}

	clientSecret, okClientSecret := os.LookupEnv("CLIENT_SECRET")

	if !okClientSecret {
		return "", "", errors.New("env variable CLIENT_SECRET is not found")
	}
	
	auth, err := GetAuthorizationToken(clientId, clientSecret)

	return "muniker", auth.AccessToken, nil
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

// List returns the stored URLs and corresponding usernames for a given credentials label
func (h Secretservice) List() (map[string]string, error) {
	credsLabelC := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabelC))

	var pathsC **C.char
	defer C.free(unsafe.Pointer(pathsC))
	var acctsC **C.char
	defer C.free(unsafe.Pointer(acctsC))
	var listLenC C.uint
	err := C.list(credsLabelC, &pathsC, &acctsC, &listLenC)
	defer C.freeListData(&pathsC, listLenC)
	defer C.freeListData(&acctsC, listLenC)
	if err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return nil, errors.New(C.GoString(errMsg))
	}

	resp := make(map[string]string)

	listLen := int(listLenC)
	if listLen == 0 {
		return resp, nil
	}
	// The maximum capacity of the following two slices is limited to (2^29)-1 to remain compatible
	// with 32-bit platforms. The size of a `*C.char` (a pointer) is 4 Byte on a 32-bit system
	// and (2^29)*4 == math.MaxInt32 + 1. -- See issue golang/go#13656
	pathTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(pathsC))[:listLen:listLen]
	acctTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(acctsC))[:listLen:listLen]
	for i := 0; i < listLen; i++ {
		resp[C.GoString(pathTmp[i])] = C.GoString(acctTmp[i])
	}

	return resp, nil
}
