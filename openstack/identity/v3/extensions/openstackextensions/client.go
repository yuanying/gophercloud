package openstackextensions

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/rackspace/gophercloud"
        "github.com/rackspace/gophercloud/openstack"
        "github.com/rackspace/gophercloud/openstack/identity/v3/extensions"
	tokens3 "github.com/rackspace/gophercloud/openstack/identity/v3/extensions/tokens"
	"github.com/rackspace/gophercloud/openstack/utils"
)

const (
	v20 = "v2.0"
	v30 = "v3.0"
)

// NewClient prepares an unauthenticated ProviderClient instance.
// Most users will probably prefer using the AuthenticatedClient function instead.
// This is useful if you wish to explicitly control the version of the identity service that's used for authentication explicitly,
// for example.
func NewClient(endpoint string) (*gophercloud.ProviderClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	hadPath := u.Path != ""
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	base := u.String()

	endpoint = gophercloud.NormalizeURL(endpoint)
	base = gophercloud.NormalizeURL(base)

	if hadPath {
		return &gophercloud.ProviderClient{
			IdentityBase:     base,
			IdentityEndpoint: endpoint,
		}, nil
	}

	return &gophercloud.ProviderClient{
		IdentityBase:     base,
		IdentityEndpoint: "",
	}, nil
}

// AuthenticatedClient logs in to an OpenStack cloud found at the identity endpoint specified by options, acquires a token, and
// returns a Client instance that's ready to operate.
// It first queries the root identity endpoint to determine which versions of the identity service are supported, then chooses
// the most recent identity service available to proceed.
func AuthenticatedClient(options extensions.AuthOptions) (*gophercloud.ProviderClient, error) {
	client, err := NewClient(options.IdentityEndpoint)
	if err != nil {
		return nil, err
	}

	err = Authenticate(client, options)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Authenticate or re-authenticate against the most recent identity service supported at the provided endpoint.
func Authenticate(client *gophercloud.ProviderClient, options extensions.AuthOptions) error {
	versions := []*utils.Version{
		{ID: v20, Priority: 20, Suffix: "/v2.0/"},
		{ID: v30, Priority: 30, Suffix: "/v3/"},
	}

	chosen, endpoint, err := utils.ChooseVersion(client, versions)
	if err != nil {
		return err
	}

	switch chosen.ID {
	case v30:
		return v3auth(client, endpoint, options)
	default:
		// The switch statement must be out of date from the versions list.
		return fmt.Errorf("Unrecognized identity version: %s", chosen.ID)
	}
}


// AuthenticateV3 explicitly authenticates against the identity v3 service.
func AuthenticateV3(client *gophercloud.ProviderClient, options extensions.AuthOptions) error {
	return v3auth(client, "", options)
}

//AuthenticateV3Trust method for TrustId support is needs to be called directly.
func AuthenticateV3Trust(client *gophercloud.ProviderClient, options extensions.AuthOptions) error {
	return v3auth(client, "", options)
}

func v3auth(client *gophercloud.ProviderClient, endpoint string, options extensions.AuthOptions) error {
        //In case of Trust TokenId would be Provided so we have to populate the value in service client
        //to not throw password error,also if it is not provided it will be empty which maintains
        //the current implementation.
        client.TokenID = options.TokenID
	// Override the generated service endpoint with the one returned by the version endpoint.
	v3Client := NewIdentityV3(client)
	if endpoint != "" {
		v3Client.Endpoint = endpoint
	}

	// copy the auth options to a local variable that we can change. `options`
	// needs to stay as-is for reauth purposes
	v3Options := options

	var scope *tokens3.Scope

        if options.TrustID != "" {
		scope = &tokens3.Scope{
			TrustID:    options.TrustID,
		}
	} else if options.TenantID != "" {
		scope = &tokens3.Scope{
			ProjectID: options.TenantID,
		}
		v3Options.TenantID = ""
		v3Options.TenantName = ""
	} else {
		if options.TenantName != "" {
			scope = &tokens3.Scope{
				ProjectName: options.TenantName,
				DomainID:    options.DomainID,
				DomainName:  options.DomainName,
			}
			v3Options.TenantName = ""
		}
	}

	result := tokens3.Create(v3Client, v3Options, scope)

	token, err := result.ExtractToken()
	if err != nil {
		return err
	}

	catalog, err := result.ExtractServiceCatalog()
	if err != nil {
		return err
	}

	client.TokenID = token.ID

	if options.AllowReauth {
		client.ReauthFunc = func() error {
			client.TokenID = ""
			return v3auth(client, endpoint, options)
		}
	}
	client.EndpointLocator = func(opts gophercloud.EndpointOpts) (string, error) {
		return openstack.TrustV3EndpointURL(catalog, opts)
	}

	return nil
}


// NewIdentityV3 creates a ServiceClient that may be used to access the v3 identity service.
func NewIdentityV3(client *gophercloud.ProviderClient) *gophercloud.ServiceClient {
	v3Endpoint := client.IdentityBase + "v3/"

	return &gophercloud.ServiceClient{
		ProviderClient: client,
		Endpoint:       v3Endpoint,
	}
}


func NewIdentityAdminV3(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) (*gophercloud.ServiceClient, error) {
	eo.ApplyDefaults("identity")
	eo.Availability = gophercloud.AvailabilityAdmin

	url, err := client.EndpointLocator(eo)
	if err != nil {
		return nil, err
	}

	// Force using v3 API
	if strings.Contains(url, "/v2.0") {
		url = strings.Replace(url, "/v2.0", "/v3", -1)
	}

	return &gophercloud.ServiceClient{ProviderClient: client, Endpoint: url}, nil
}
