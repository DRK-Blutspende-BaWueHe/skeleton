package skeleton

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"github.com/MicahParks/keyfunc"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type authManager struct {
	restClient            *resty.Client
	jwks                  *keyfunc.JWKS
	oIDCBaseURL           string
	clientId              string
	clientSecret          string
	oidc                  *openIDConfiguration
	oidcMutex             sync.Mutex
	tokenEndpointResponse *tokenEndpointResponse
}

type AuthManager interface {
	GetJWKS() (*keyfunc.JWKS, error)
	GetClientCredential() (string, error)
	InvalidateClientCredential()
}

func NewAuthManager(OIDCBaseURL, clientId, clientSecret string) AuthManager {
	authManager := &authManager{
		restClient:   resty.New(), // this resty is only for the authmanager and its connection to the ciam
		clientId:     clientId,
		clientSecret: clientSecret,
		oIDCBaseURL:  OIDCBaseURL,
	}

	err := authManager.loadJWKS()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load OIDC from the authentication provider")
		return nil
	}

	return authManager
}

type openIDConfiguration struct {
	Issuer                                                    string   `json:"issuer"`
	AuthorizationEndpoint                                     string   `json:"authorization_endpoint"`
	TokenEndpoint                                             string   `json:"token_endpoint"`
	IntrospectionEndpoint                                     string   `json:"introspection_endpoint"`
	UserinfoEndpoint                                          string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                                        string   `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                        bool     `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                               bool     `json:"frontchannel_logout_supported"`
	JwksURI                                                   string   `json:"jwks_uri"`
	CheckSessionIframe                                        string   `json:"check_session_iframe"`
	GrantTypesSupported                                       []string `json:"grant_types_supported"`
	AcrValuesSupported                                        []string `json:"acr_values_supported"`
	ResponseTypesSupported                                    []string `json:"response_types_supported"`
	SubjectTypesSupported                                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported                          []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported                       []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported                       []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported                         []string `json:"userinfo_signing_alg_values_supported"`
	UserinfoEncryptionAlgValuesSupported                      []string `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported                      []string `json:"userinfo_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported                    []string `json:"request_object_signing_alg_values_supported"`
	RequestObjectEncryptionAlgValuesSupported                 []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported                 []string `json:"request_object_encryption_enc_values_supported"`
	ResponseModesSupported                                    []string `json:"response_modes_supported"`
	RegistrationEndpoint                                      string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported                []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpointAuthMethodsSupported                 []string `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	AuthorizationSigningAlgValuesSupported                    []string `json:"authorization_signing_alg_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string `json:"authorization_encryption_enc_values_supported"`
	ClaimsSupported                                           []string `json:"claims_supported"`
	ClaimTypesSupported                                       []string `json:"claim_types_supported"`
	ClaimsParameterSupported                                  bool     `json:"claims_parameter_supported"`
	ScopesSupported                                           []string `json:"scopes_supported"`
	RequestParameterSupported                                 bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported                              bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             bool     `json:"require_request_uri_registration"`
	CodeChallengeMethodsSupported                             []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens                     bool     `json:"tls_client_certificate_bound_access_tokens"`
	RevocationEndpoint                                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	BackchannelLogoutSupported                                bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported                         bool     `json:"backchannel_logout_session_supported"`
	DeviceAuthorizationEndpoint                               string   `json:"device_authorization_endpoint"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported"`
	BackchannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported"`
	RequirePushedAuthorizationRequests                        bool     `json:"require_pushed_authorization_requests"`
	PushedAuthorizationRequestEndpoint                        string   `json:"pushed_authorization_request_endpoint"`
	MtlsEndpointAliases                                       struct {
		TokenEndpoint                      string `json:"token_endpoint"`
		RevocationEndpoint                 string `json:"revocation_endpoint"`
		IntrospectionEndpoint              string `json:"introspection_endpoint"`
		DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
		RegistrationEndpoint               string `json:"registration_endpoint"`
		UserinfoEndpoint                   string `json:"userinfo_endpoint"`
		PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
		BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
	} `json:"mtls_endpoint_aliases"`
}

type tokenEndpointResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int64  `json:"not-before-policy"`
	Scope            string `json:"scope"`
}

// OIDC Config endpoint. See here for more https://openid.net/connect/
const oidcURLPart = "/.well-known/openid-configuration"

func (m *authManager) GetJWKS() (*keyfunc.JWKS, error) {
	if m.jwks == nil {
		if err := m.loadJWKS(); err != nil {
			return nil, err
		}
	}
	return m.jwks, nil
}

// Get the AccessToken.
func (m *authManager) GetClientCredential() (string, error) {
	if m.tokenEndpointResponse == nil {
		err := m.refreshClientCredential()
		if err != nil || m.tokenEndpointResponse == nil {
			return "", errors.New("no client credential")
		}
	}
	return m.tokenEndpointResponse.AccessToken, nil
}

func (m *authManager) InvalidateClientCredential() {
	m.tokenEndpointResponse = nil
}

func (m *authManager) refreshClientCredential() error {
	if err := m.ensureOIDC(); err != nil {
		return err
	}

	tokenEndpointResponse, err := m.callAuthProviderTokenEndpoint()
	if tokenEndpointResponse == nil || err != nil {
		log.Error().Err(err).Msg("Failed to load JWT token from the authentication provider")
		return err
	}

	if tokenEndpointResponse.TokenType != "Bearer" {
		log.Error().Msg("Got invalid token type from the authentication provider")
		return errors.New("invalid token type")
	}

	m.tokenEndpointResponse = tokenEndpointResponse

	return nil
}

func (m *authManager) loadJWKS() error {
	if err := m.ensureOIDC(); err != nil {
		return err
	}

	jwks, err := keyfunc.Get(m.oidc.JwksURI, keyfunc.Options{
		Client:              m.restClient.GetClient(),
		RefreshErrorHandler: m.refreshErrorHandler,
		RefreshUnknownKID:   true,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to get JWKS from the authentication provider")
		return err
	}

	m.jwks = jwks

	return nil
}

func (m *authManager) refreshErrorHandler(err error) {
	log.Error().Err(err).Msg("Failed to get and refresh JWKS from the authentication provider")
}

func (m *authManager) callAuthProviderOIDCEndpoint() (*openIDConfiguration, error) {
	response, err := m.restClient.R().
		SetHeader("Content-Type", "application/json").
		SetResult(&openIDConfiguration{}).
		Get(strings.TrimRight(m.oIDCBaseURL, "/") + oidcURLPart)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get OIDC from the authentication provider")
		return nil, err
	}

	if !response.IsSuccess() {
		log.Error().Err(err).Msgf("Failed to get OIDC from the authentication provider: %s", response.Status())
		return nil, err
	}

	oidc := response.Result().(*openIDConfiguration)

	return oidc, nil
}

func (m *authManager) callAuthProviderTokenEndpoint() (*tokenEndpointResponse, error) {
	response, err := m.restClient.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Cache-Control", "no-cache").
		SetAuthScheme("Basic").
		SetAuthToken(base64.StdEncoding.EncodeToString([]byte(m.clientId + ":" + m.clientSecret))).
		SetResult(&tokenEndpointResponse{}).
		SetFormData(map[string]string{"grant_type": "client_credentials"}).
		Post(m.oidc.TokenEndpoint)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get JWT token from the authentication provider's token endpoint")
		return nil, err
	}

	if !response.IsSuccess() {
		log.Error().Err(err).Msgf("Failed to get JWT token from the authentication provider's token endpoint: %s", response.Status())
		return nil, err
	}

	tokenEndpointResponse := response.Result().(*tokenEndpointResponse)

	return tokenEndpointResponse, nil
}

func (m *authManager) ensureOIDC() error {
	if m.oidc == nil {
		oidc, err := m.callAuthProviderOIDCEndpoint()
		if err != nil {
			log.Error().Err(err).Msg("Failed to load OIDC from the authentication provider")
			return err
		}
		m.updateOIDC(oidc)
	}
	return nil
}

func (m *authManager) updateOIDC(oidc *openIDConfiguration) {
	m.oidcMutex.Lock()
	m.oidc = oidc
	m.oidcMutex.Unlock()
}
