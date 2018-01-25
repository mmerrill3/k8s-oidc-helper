package helper

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

type ConfigFile struct {
	Installed *GoogleConfig `json:"installed"`
}

type GoogleConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token,omitempty"`
}

func ReadConfig(path string) (*GoogleConfig, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	cf := &ConfigFile{}
	err = json.NewDecoder(f).Decode(cf)
	if err != nil {
		return nil, err
	}
	return cf.Installed, nil
}

// Get the id_token and refresh_token from google
func GetToken(clientID, clientSecret, code string) (*TokenResponse, error) {
	val := url.Values{}
	val.Add("grant_type", "authorization_code")
	val.Add("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")
	val.Add("client_id", clientID)
	val.Add("client_secret", clientSecret)
	val.Add("code", code)

	resp, err := http.PostForm("https://www.googleapis.com/oauth2/v3/token", val)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	tr := &TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tr)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// Get the id_token from the oauth2-proxy's cookie
func GetTokenFromCookie(cookie, cookieURL string) (*TokenResponse, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", cookieURL, nil)
	fmt.Printf("Using cookie URL %s\n", cookieURL)
	req.Header.Set("cookie", "_oauth2_proxy="+cookie)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error while sending GET to oauth2_proxy %s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	tr := &TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tr)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

func GetTokenFromAuth(auth string) (*TokenResponse, error) {
    tr := &TokenResponse{}
    err := json.Unmarshal([]byte(auth), tr)
	if err != nil {
		return nil, err
	}
    return tr, nil
}

type KubectlUser struct {
	Name         string        `yaml:"name"`
	KubeUserInfo *KubeUserInfo `yaml:"user"`
}

type KubeUserInfo struct {
	AuthProvider *AuthProvider `yaml:"auth-provider"`
}

type AuthProvider struct {
	APConfig *APConfig `yaml:"config"`
	Name     string    `yaml:"name"`
}

type APConfig struct {
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	IdToken      string `yaml:"id-token"`
	IdpIssuerUrl string `yaml:"idp-issuer-url"`
	RefreshToken string `yaml:"refresh-token"`
}

type UserInfo struct {
	Email string `json:"email"`
}

func GetUserEmail(accessToken string) (string, error) {
	uri, _ := url.Parse("https://www.googleapis.com/oauth2/v1/userinfo")
	q := uri.Query()
	q.Set("alt", "json")
	q.Set("access_token", accessToken)
	uri.RawQuery = q.Encode()
	resp, err := http.Get(uri.String())
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}
	ui := &UserInfo{}
	err = json.NewDecoder(resp.Body).Decode(ui)
	if err != nil {
		return "", err
	}
	return ui.Email, nil
}

func GenerateAuthInfo(clientId, clientSecret, idToken, refreshToken string) *clientcmdapi.AuthInfo {
	return &clientcmdapi.AuthInfo{
		AuthProvider: &clientcmdapi.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      clientId,
				"client-secret":  clientSecret,
				"id-token":       idToken,
				"idp-issuer-url": "https://accounts.google.com",
				"refresh-token":  refreshToken,
			},
		},
	}
}

func createOpenCmd(url string) (*exec.Cmd, error) {

	switch os := runtime.GOOS; os {
	case "darwin":
		return exec.Command("open", url), nil
	case "linux":
		return exec.Command("xdg-open", url), nil
	}

	return nil, fmt.Errorf("Could not detect the open command for OS: %s", runtime.GOOS)
}

func LaunchBrowser(openBrowser bool, oauthUrl, clientID string) {
    url := fmt.Sprintf(oauthUrl, clientID)
	openInstructions := fmt.Sprintf("Open this url in your browser: %s\n", url)

	if !openBrowser {
		fmt.Print(openInstructions)
		return
	}

	cmd, err := createOpenCmd(url)
	if err != nil {
		fmt.Print(openInstructions)
		return
	}

	err = cmd.Start()
	if err != nil {
		fmt.Print(openInstructions)
	}
}

func SetSTTY() {
    fmt.Print("setting stty -icanon")
    cmd := exec.Command("stty", "-icanon")
    out, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Printf("cmd.Run() failed with %s\n", err)
    }
    fmt.Printf("combined out:\n%s\n", string(out))
}

func LaunchBrowserToCopyCookie(openBrowser bool, oauthUrl, clientID string) {
	openInstructions := fmt.Sprintf("Open this url in your browser: %s\n", fmt.Sprintf(oauthUrl, clientID))
    oauthUrl="https://dashboard.k8s.ctnrva0.dev.vonagenetworks.net/exchangeCookie"

    cmd, err := createOpenCmd(oauthUrl)
    if err != nil {
        fmt.Print(openInstructions)
        return
    }

    err = cmd.Start()
    if err != nil {
        fmt.Print(openInstructions)
    }
}
