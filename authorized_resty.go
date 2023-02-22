package skeleton

// Return an authorized Resty. Expired tokens get updated automacially - its the "no-worry solution for services"
import (
	"context"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"net/http"
)

func NewAuthorizedResty(ctx context.Context, OIDCBaseURL, clientId, clientSecret string) *resty.Client {
	authManager := &authManager{
		restClient:   resty.New(), // this resty is only for the authmanager and its connection to the iam
		clientId:     clientId,
		clientSecret: clientSecret,
		oIDCBaseURL:  OIDCBaseURL,
	}

	client := resty.New().
		SetRetryCount(2).
		AddRetryCondition(func(response *resty.Response, err error) bool { // retry only on 401 ...
			if response.StatusCode() == http.StatusUnauthorized {
				authManager.InvalidateClientCredential()
				return true
			}
			return false
		}).
		OnBeforeRequest(func(client *resty.Client, request *resty.Request) error { // make sure context is set in case of freeze
			request.SetContext(ctx)
			return nil
		}).
		OnBeforeRequest(func(client *resty.Client, request *resty.Request) error { // update Token
			authToken, err := authManager.GetClientCredential()
			if err != nil {
				log.Error().Err(err).Msg("refresh internal api client auth token failed")
				return err
			}
			client.SetAuthToken(authToken)
			return nil
		})

	err := authManager.loadJWKS()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load OIDC from the authentication provider")
		return nil
	}

	return client
}
