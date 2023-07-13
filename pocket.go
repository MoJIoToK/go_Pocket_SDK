package pocket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// "bytes"
// "context"
// "encoding/json"
// "fmt"
// "github.com/pkg/errors"
// "io/ioutil"
// "net/http"
// "strings"
// "time"

const (
	HOST                    = "https://getpocket.com/v3"
	AUTORIZEURL             = "https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s"
	END_POINT_ADD           = "/add"
	END_POINT_REQUEST_TOKEN = "/oauth/request"
	END_POINT_AUTHORIZE     = "/oauth/authorize"

	X_ERROR_HEADER  = "X-Error"
	DEFAULT_TIMEOUT = 5 * time.Second
)

type (
	requestTokenRequest struct {
		ConsumerKey string `json:"consumer_key"`
		RedirectURI string `json:"redirect_uri"`
	}

	authorizeRequest struct {
		ConsumerKey string `json:"consumer_key"`
		Code        string `json:"code"`
	}

	AuthorizeResponse struct {
		AccessToken string `json:"access_token"`
		Username    string `json:"username"`
	}

	addRequest struct {
		URL         string `json:"url"`
		Title       string `json:"title,omitempty"`
		Tags        string `json:"tags,omitempty"`
		AccessToken string `json:"access_token"`
		ConsumerKey string `json:"consumer_key"`
	}

	// AddInput holds data necessary to create new item in Pocket list
	AddInput struct {
		URL         string
		Title       string
		Tags        []string
		AccessToken string
	}
)

// checking URL and Access Token for data availability. They must not be empty
func (i AddInput) validate() error {
	if i.URL == "" {
		return errors.New("required URL values is empty")
	}
	if i.AccessToken == "" {
		return errors.New("access token is empty")
	}
	return nil
}

func (i AddInput) generateRequest(ConsumerKey string) addRequest {
	return addRequest{
		URL:         i.URL,
		Tags:        strings.Join(i.Tags, ","),
		Title:       i.Title,
		AccessToken: i.AccessToken,
		ConsumerKey: ConsumerKey,
	}
}

// Client is a getpocket API client
type Client struct {
	client      *http.Client
	ConsumerKey string
}

// newClient creates a new client instance with your app key (to generate key
// visit https://getpocket.com/developer/apps/))
func NewClient(ConsumerKey string) (*Client, error) {
	if ConsumerKey == "" {
		return nil, errors.New("Consumer key is empty")
	}

	return &Client{
		client: &http.Client{
			Timeout: DEFAULT_TIMEOUT,
		},
		ConsumerKey: ConsumerKey,
	}, nil
}

// GetRequestToken obtains the request token that is used to authorize user in your app
func (c *Client) GetRequestToken(ctx context.Context, redirectURI string) (string, error) {
	inp := &requestTokenRequest{
		ConsumerKey: c.ConsumerKey,
		RedirectURI: redirectURI,
	}

	values, err := c.doHTTP(ctx, END_POINT_REQUEST_TOKEN, inp)
	if err != nil {
		return "", err
	}

	if values.Get("code") == "" {
		return "", errors.New("empty request token in API response")
	}

	return values.Get("code"), nil
}

// GetAuthorizationURL generates link to authorize user
func (c *Client) GetAuthorizationURL(requestToken, redirectURI string) (string, error) {
	if requestToken == "" || redirectURI == "" {
		return "", errors.New("empty params")
	}

	return fmt.Sprintf(AUTORIZEURL, requestToken, redirectURI), nil
}

// Authorize generates access token for user, that authorized in your app via link
func (c *Client) Authorize(ctx context.Context, requestToken string) (*AuthorizeResponse, error) {
	if requestToken == "" {
		return nil, errors.New("empty request token")
	}

	inp := &authorizeRequest{
		Code:        requestToken,
		ConsumerKey: c.ConsumerKey,
	}

	values, err := c.doHTTP(ctx, END_POINT_AUTHORIZE, inp)
	if err != nil {
		return nil, err
	}

	accessToken, username := values.Get("access_token"), values.Get("username")
	if accessToken == "" {
		return nil, errors.New("empty access token in API response")
	}

	return &AuthorizeResponse{
		AccessToken: accessToken,
		Username:    username,
	}, nil
}

// Add creates new item in Poccket list
func (c *Client) Add(ctx context.Context, input AddInput) error {
	if err := input.validate(); err != nil {
		return err
	}

	req := input.generateRequest(c.ConsumerKey)
	_, err := c.doHTTP(ctx, END_POINT_ADD, req)

	return err
}

func (c *Client) doHTTP(ctx context.Context, endpoint string, body interface{}) (url.Values, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to marshal input body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, HOST+endpoint, bytes.NewBuffer(b))
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to create new request")
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF8")

	resp, err := c.client.Do(req)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to send http request")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Sprintf("API Error: %s", resp.Header.Get(X_ERROR_HEADER))
		return url.Values{}, errors.New(err)
	}

	respB, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to read request body")
	}

	values, err := url.ParseQuery(string(respB))
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to parse body")
	}

	return values, nil
}
