package hsdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/philips-software/go-hsdp-api/iam"
	"golang.org/x/oauth2"
)

func (c *HSDPConnector) introspect(ctx context.Context, tokenSource oauth2.TokenSource) (*iam.IntrospectResponse, error) {
	if c.introspectURI == "" {
		return nil, errors.New("hsdp: introspect endpoint is missing")
	}

	req, err := http.NewRequest("POST", c.introspectURI, nil)
	if err != nil {
		return nil, fmt.Errorf("hsdp: create GET request: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("hsdp: get access token: %v", err)
	}

	form := url.Values{}
	form.Add("token", token.AccessToken)
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	req.ContentLength = int64(len(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Api-Version", "4")
	req.SetBasicAuth(c.oauth2Config.ClientID, c.oauth2Config.ClientSecret)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var introspectResponse iam.IntrospectResponse
	if err := json.Unmarshal(body, &introspectResponse); err != nil {
		return nil, fmt.Errorf("hsdp: failed to decode introspect: %v", err)
	}
	return &introspectResponse, nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}
