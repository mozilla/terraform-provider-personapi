package person_api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	auth0ClientID     string
	auth0ClientSecret string
	auth0Audience     string
	auth0Endpoint     string
	auth0Scopes       []string
	httpClient        *http.Client
	personEndpoint    string

	auth0AccessToken string
}

// userAgentRoundTripper sets a User-Agent header on every outbound request that
// does not already specify one, then delegates to the wrapped RoundTripper.
type userAgentRoundTripper struct {
	userAgent string
	next      http.RoundTripper
}

func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Per the RoundTripper contract the request must not be mutated, so clone it
	// before adding the header.
	r := req.Clone(req.Context())
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", rt.userAgent)
	}
	return rt.next.RoundTrip(r)
}

func NewClient(auth0ClientID string, auth0ClientSecret string, auth0Audience string, auth0Endpoint string, auth0Scopes []string, personEndpoint string, userAgent string) *Client {
	c := &Client{
		auth0ClientID:     auth0ClientID,
		auth0ClientSecret: auth0ClientSecret,
		auth0Audience:     auth0Audience,
		auth0Endpoint:     auth0Endpoint,
		auth0Scopes:       auth0Scopes,
		httpClient: &http.Client{
			Transport: &userAgentRoundTripper{userAgent: userAgent, next: http.DefaultTransport},
		},
		personEndpoint: personEndpoint,
	}

	return c
}

func (client *Client) GetAccessToken(ctx context.Context) error {
	oauth2_config := clientcredentials.Config{
		ClientID:       client.auth0ClientID,
		ClientSecret:   client.auth0ClientSecret,
		EndpointParams: url.Values{"audience": {client.auth0Audience}},
		Scopes:         client.auth0Scopes,
		TokenURL:       client.auth0Endpoint,
	}

	// Use our own HTTP client for the token request so it carries the same
	// User-Agent header as the Person API calls.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client.httpClient)

	oauth_token, err := oauth2_config.Token(ctx)
	tflog.Info(ctx, fmt.Sprintf("HTTP Request: %#v", oauth_token))

	if err == nil {
		client.auth0AccessToken = oauth_token.AccessToken
	}

	return err
}

func (client *Client) GetPersonByEmail(ctx context.Context, email string) (*Person, error) {
	person := Person{}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", client.personEndpoint+"/v2/user/primary_email/"+email, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Add("Authorization", "Bearer "+client.auth0AccessToken)

	httpResp, err := client.httpClient.Do(httpReq)
	tflog.Info(ctx, fmt.Sprintf("HTTP Request: %#v", httpReq))
	if err != nil {
		return nil, err
	}

	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("Person API responded with status code %d", httpResp.StatusCode)
	}

	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(respBody, &person)
	if err != nil {
		return nil, err
	}

	flattenAccessInformation(&person)

	return &person, nil
}

// GetUsersByAttributes returns the full profiles of all active users matching
// the given attribute filters, following pagination until exhausted. When
// ldapGroup is non-empty, results are filtered by LDAP group membership
// (access_information.ldap). When staff is non-nil, results are filtered by
// whether the person is Mozilla staff (staff_information.staff). At least one
// filter should be supplied.
func (client *Client) GetUsersByAttributes(ctx context.Context, ldapGroup string, staff *bool) ([]Person, error) {
	var people []Person

	endpoint := client.personEndpoint + "/v2/users/id/all/by_attribute_contains"

	query := url.Values{}
	query.Set("fullProfiles", "True")
	query.Set("active", "True")
	if ldapGroup != "" {
		query.Set("access_information.ldap", ldapGroup)
	}
	if staff != nil {
		// The API expects capitalized boolean values, matching active=True above.
		staffValue := "False"
		if *staff {
			staffValue = "True"
		}
		query.Set("staff_information.staff", staffValue)
	}

	for {
		httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}

		httpReq.Header.Add("Authorization", "Bearer "+client.auth0AccessToken)

		httpResp, err := client.httpClient.Do(httpReq)
		tflog.Info(ctx, fmt.Sprintf("HTTP Request: %#v", httpReq))
		if err != nil {
			return nil, err
		}

		if httpResp.StatusCode >= 400 {
			httpResp.Body.Close()
			return nil, fmt.Errorf("Person API responded with status code %d", httpResp.StatusCode)
		}

		respBody, err := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		if err != nil {
			return nil, err
		}

		var page UsersByAttributeResponse
		if err := json.Unmarshal(respBody, &page); err != nil {
			return nil, err
		}

		for i := range page.Users {
			person := page.Users[i].Profile
			flattenAccessInformation(&person)
			people = append(people, person)
		}

		// nextPage is empty (or null) once all pages have been returned.
		next := page.NextPage
		if next == "" || next == "null" {
			break
		}

		// Pass the token back verbatim, as the API documentation instructs.
		query.Set("nextPage", next)
	}

	return people, nil
}

// flattenAccessInformation converts the Mozilliansorg and LDAP access information
// Values maps into lists of group names stored in their respective List fields.
func flattenAccessInformation(person *Person) {
	person.AccessInformation.Mozilliansorg.List = mapKeys(person.AccessInformation.Mozilliansorg.Values)
	person.AccessInformation.LDAP.List = mapKeys(person.AccessInformation.LDAP.Values)
}

// mapKeys returns the keys of m as a slice of strings.
func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
