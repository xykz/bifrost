package tokencache

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ccConfig(tokenURL string) *schemas.OAuthKeyConfig {
	return &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantClientCredentials,
		TokenURL:     *schemas.NewSecretVar(tokenURL),
		ClientID:     schemas.NewSecretVar("id"),
		ClientSecret: schemas.NewSecretVar("secret"),
		Scopes:       []string{"all-apis"},
	}
}

func TestResolveBearer(t *testing.T) {
	t.Run("a static value wins and costs no mint", func(t *testing.T) {
		ts := newTokenServer(t)
		cache := New[string](Options{})
		h, bErr := ResolveBearer(context.Background(), cache, "static", ccConfig(ts.URL), authClient(t))
		require.Nil(t, bErr)
		assert.Equal(t, map[string]string{"Authorization": "Bearer static"}, h)
		hits, _, _, _, _ := ts.snapshot()
		assert.Equal(t, 0, hits)
	})

	t.Run("no value and no config is keyless", func(t *testing.T) {
		h, bErr := ResolveBearer(context.Background(), New[string](Options{}), "", nil, nil)
		require.Nil(t, bErr)
		require.NotNil(t, h)
		assert.Empty(t, h)
	})

	t.Run("mints once and reuses across calls", func(t *testing.T) {
		ts := newTokenServer(t)
		cache := New[string](Options{})
		cfg := ccConfig(ts.URL)
		for range 3 {
			h, bErr := ResolveBearer(context.Background(), cache, "", cfg, authClient(t))
			require.Nil(t, bErr)
			assert.Equal(t, "Bearer minted", h["Authorization"])
		}
		hits, form, user, pass, _ := ts.snapshot()
		assert.Equal(t, 1, hits)
		assert.Equal(t, "all-apis", form.Get("scope"))
		assert.Equal(t, "id", user)
		assert.Equal(t, "secret", pass)
	})

	t.Run("a rejected credential is reported once per backoff window", func(t *testing.T) {
		ts := newTokenServer(t)
		ts.set(http.StatusUnauthorized, `{"error":"invalid_client"}`, nil)
		cache := New[string](Options{})
		cfg := ccConfig(ts.URL)
		for range 5 {
			h, bErr := ResolveBearer(context.Background(), cache, "", cfg, authClient(t))
			assert.Nil(t, h)
			require.NotNil(t, bErr)
			assert.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
		}
		hits, _, _, _, _ := ts.snapshot()
		assert.Equal(t, 1, hits)
	})

	t.Run("a config fault never reaches the network", func(t *testing.T) {
		ts := newTokenServer(t)
		cfg := ccConfig(ts.URL)
		cfg.ClientSecret = nil
		h, bErr := ResolveBearer(context.Background(), New[string](Options{}), "", cfg, authClient(t))
		assert.Nil(t, h)
		require.NotNil(t, bErr)
		assert.Contains(t, bErr.Error.Message, "client_secret")
		require.NotNil(t, bErr.AllowFallbacks)
		assert.False(t, *bErr.AllowFallbacks)
		hits, _, _, _, _ := ts.snapshot()
		assert.Equal(t, 0, hits)
	})
}

func TestMinterForConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*schemas.OAuthKeyConfig)
		want string
	}{
		{"nil config", nil, "oauth_key_config is not set"},
		{"missing token url", func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar(" ") }, "token_url is required"},
		{"relative token url", func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("/oauth/token") }, "must be https"},
		{"ftp token url", func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("ftp://x/token") }, "must be https"},
		{"plain http on a public host", func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("http://idp.example/oauth2/token") }, "must be https"},
		{"missing grant", func(c *schemas.OAuthKeyConfig) { c.GrantType = "" }, "grant_type is required"},
		{"unknown grant", func(c *schemas.OAuthKeyConfig) { c.GrantType = "password" }, "must be client_credentials, jwt_bearer or browser_login"},
		{"jwt bearer without key", func(c *schemas.OAuthKeyConfig) {
			c.GrantType = schemas.OAuthGrantJWTBearer
			c.Issuer = "i"
			c.Audience = "a"
		}, "private_key, oauth_key_config.issuer and oauth_key_config.audience are required"},
		{"jwt bearer without issuer", func(c *schemas.OAuthKeyConfig) {
			c.GrantType = schemas.OAuthGrantJWTBearer
			c.PrivateKey = schemas.NewSecretVar("pem")
			c.Audience = "a"
		}, "private_key, oauth_key_config.issuer and oauth_key_config.audience are required"},
		{"jwt bearer bad algorithm", func(c *schemas.OAuthKeyConfig) {
			c.GrantType = schemas.OAuthGrantJWTBearer
			c.PrivateKey = schemas.NewSecretVar("pem")
			c.Issuer, c.Audience, c.SigningAlgorithm = "i", "a", "HS256"
		}, "signing_algorithm must be one of"},
		{"missing client id", func(c *schemas.OAuthKeyConfig) { c.ClientID = schemas.NewSecretVar("") }, "client_id and oauth_key_config.client_secret are required"},
		{"bad auth style", func(c *schemas.OAuthKeyConfig) { c.AuthStyle = "query" }, "auth_style must be header or body"},
		{"browser login without a refresh token", func(c *schemas.OAuthKeyConfig) {
			c.GrantType = schemas.OAuthGrantBrowserLogin
			c.RefreshToken = nil
		}, "refresh_token is required for the browser_login grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *schemas.OAuthKeyConfig
			if tc.edit != nil {
				cfg = ccConfig("https://idp.example/token")
				tc.edit(cfg)
			}
			_, mint, bErr := MinterForConfig(cfg, nil)
			assert.Nil(t, mint)
			require.NotNil(t, bErr)
			assert.Contains(t, bErr.Error.Message, tc.want)
			require.NotNil(t, bErr.AllowFallbacks)
			assert.False(t, *bErr.AllowFallbacks)
		})
	}

	t.Run("plain http is accepted for loopback hosts only", func(t *testing.T) {
		for _, u := range []string{"http://127.0.0.1:9/token", "http://localhost:9/token", "http://[::1]:9/token"} {
			_, mint, bErr := MinterForConfig(ccConfig(u), nil)
			assert.Nil(t, bErr, u)
			assert.NotNil(t, mint, u)
		}
	})

	t.Run("plain http to a host that merely looks like loopback is rejected", func(t *testing.T) {
		// The client secret rides on this request, so only a real loopback address may skip TLS.
		// A public name such as 127.attacker.example resolves wherever its owner wants.
		for _, u := range []string{
			"http://127.attacker.example/token",
			"http://127.0.0.1.evil.example/token",
			"http://localhost.evil.example/token",
			"http://[::1]evil/token",
			"http://10.0.0.1/token",
		} {
			_, mint, bErr := MinterForConfig(ccConfig(u), nil)
			require.NotNil(t, bErr, u)
			assert.Nil(t, mint, u)
			assert.Contains(t, bErr.Error.Message, "must be https", u)
		}
		for _, u := range []string{"http://127.0.0.2:9/token", "http://[::1]:9/token", "http://LOCALHOST/token"} {
			_, mint, bErr := MinterForConfig(ccConfig(u), nil)
			assert.Nil(t, bErr, u)
			assert.NotNil(t, mint, u)
		}
	})

	t.Run("a jwt_bearer config yields a minter that signs on the cold path only", func(t *testing.T) {
		cfg := &schemas.OAuthKeyConfig{
			GrantType:  schemas.OAuthGrantJWTBearer,
			TokenURL:   *schemas.NewSecretVar("https://idp.example/token"),
			PrivateKey: schemas.NewSecretVar("not parsed until mint"),
			Issuer:     "i",
			Audience:   "a",
		}
		_, mint, bErr := MinterForConfig(cfg, nil)
		require.Nil(t, bErr)
		_, bErr = mint(context.Background(), nil)
		require.NotNil(t, bErr, "the bad PEM surfaces at mint time")
		assert.Contains(t, bErr.Error.Message, "PKCS#1 or PKCS#8")
	})

	t.Run("valid config yields a stable key and a minter", func(t *testing.T) {
		k1, m1, bErr := MinterForConfig(ccConfig("https://idp.example/token"), nil)
		require.Nil(t, bErr)
		require.NotNil(t, m1)
		k2, _, _ := MinterForConfig(ccConfig("https://idp.example/token"), nil)
		assert.Equal(t, k1, k2)
	})
}

func TestOAuthKeyCacheKey(t *testing.T) {
	base := func() *schemas.OAuthKeyConfig { return ccConfig("https://idp.example/token") }
	key := func(c *schemas.OAuthKeyConfig) string {
		k, _, bErr := MinterForConfig(c, nil)
		require.Nil(t, bErr)
		return k
	}
	ref := key(base())

	for _, tc := range []struct {
		name string
		edit func(*schemas.OAuthKeyConfig)
	}{
		{"token url", func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("https://idp.example/token2") }},
		{"client id", func(c *schemas.OAuthKeyConfig) { c.ClientID = schemas.NewSecretVar("id2") }},
		{"client secret", func(c *schemas.OAuthKeyConfig) { c.ClientSecret = schemas.NewSecretVar("secret2") }},
		{"scopes", func(c *schemas.OAuthKeyConfig) { c.Scopes = []string{"other"} }},
		{"audience", func(c *schemas.OAuthKeyConfig) { c.Audience = "aud" }},
		{"auth style", func(c *schemas.OAuthKeyConfig) { c.AuthStyle = schemas.OAuthAuthStyleBody }},
		{"extra params", func(c *schemas.OAuthKeyConfig) { c.ExtraParams = map[string]string{"resource": "r"} }},
		{"grant", func(c *schemas.OAuthKeyConfig) {
			c.GrantType = schemas.OAuthGrantJWTBearer
			c.PrivateKey = schemas.NewSecretVar("pem")
			c.Issuer, c.Audience = "i", "a"
		}},
	} {
		t.Run(tc.name+" changes the key", func(t *testing.T) {
			c := base()
			tc.edit(c)
			assert.NotEqual(t, ref, key(c))
		})
	}

	t.Run("jwt_bearer fields each change the key", func(t *testing.T) {
		jwtBase := func() *schemas.OAuthKeyConfig {
			return &schemas.OAuthKeyConfig{
				GrantType:  schemas.OAuthGrantJWTBearer,
				TokenURL:   *schemas.NewSecretVar("https://idp.example/token"),
				PrivateKey: schemas.NewSecretVar("pem"),
				Issuer:     "i",
				Audience:   "a",
			}
		}
		jwtRef := key(jwtBase())
		for _, tc := range []struct {
			name string
			edit func(*schemas.OAuthKeyConfig)
		}{
			{"private key", func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar("pem2") }},
			{"issuer", func(c *schemas.OAuthKeyConfig) { c.Issuer = "i2" }},
			{"subject", func(c *schemas.OAuthKeyConfig) { c.Subject = "s" }},
			{"audience", func(c *schemas.OAuthKeyConfig) { c.Audience = "a2" }},
			{"key id", func(c *schemas.OAuthKeyConfig) { c.KeyID = "k" }},
			{"algorithm", func(c *schemas.OAuthKeyConfig) { c.SigningAlgorithm = "RS512" }},
		} {
			c := jwtBase()
			tc.edit(c)
			assert.NotEqual(t, jwtRef, key(c), tc.name)
		}
	})

	t.Run("extra params hash in a stable order", func(t *testing.T) {
		a, b := base(), base()
		a.ExtraParams = map[string]string{"x": "1", "y": "2"}
		b.ExtraParams = map[string]string{"y": "2", "x": "1"}
		assert.Equal(t, key(a), key(b))
	})

	t.Run("the key never contains the secret", func(t *testing.T) {
		assert.NotContains(t, ref, "secret")
	})

	t.Run("browser_login keys are distinguished by their refresh token", func(t *testing.T) {
		// Two browser sessions for the same endpoint must never share a cache slot: the
		// second one's access token would be served on the first one's behalf.
		browser := func(refresh string) *schemas.OAuthKeyConfig {
			return &schemas.OAuthKeyConfig{
				GrantType:    schemas.OAuthGrantBrowserLogin,
				TokenURL:     *schemas.NewSecretVar("https://api.example/refresh"),
				RefreshToken: schemas.NewSecretVar(refresh),
			}
		}
		first := key(browser("refresh-1"))
		assert.NotEqual(t, first, key(browser("refresh-2")))
		assert.NotContains(t, first, "refresh-1")
	})
}

func TestDatabricksOAuthConfig(t *testing.T) {
	t.Run("derives the fixed endpoint and scope", func(t *testing.T) {
		cfg, ok := (&schemas.DatabricksKeyConfig{
			ClientID:     schemas.NewSecretVar("sp"),
			ClientSecret: schemas.NewSecretVar("s"),
		}).OAuthConfig("dbc-1.cloud.databricks.com")
		require.True(t, ok)
		assert.Equal(t, schemas.OAuthGrantClientCredentials, cfg.GrantType)
		assert.Equal(t, "https://dbc-1.cloud.databricks.com/oidc/v1/token", cfg.TokenURL.GetValue())
		assert.Equal(t, []string{"all-apis"}, cfg.Scopes)
		assert.Equal(t, schemas.OAuthAuthStyleHeader, cfg.AuthStyle)
		_, mint, bErr := MinterForConfig(&cfg, nil)
		assert.Nil(t, bErr)
		assert.NotNil(t, mint)
	})

	t.Run("a missing half yields nothing", func(t *testing.T) {
		var none *schemas.DatabricksKeyConfig
		_, ok := none.OAuthConfig("h")
		assert.False(t, ok)
		_, ok = (&schemas.DatabricksKeyConfig{ClientID: schemas.NewSecretVar("sp")}).OAuthConfig("h")
		assert.False(t, ok)
		_, ok = (&schemas.DatabricksKeyConfig{ClientID: schemas.NewSecretVar("sp"), ClientSecret: schemas.NewSecretVar("")}).OAuthConfig("h")
		assert.False(t, ok)
	})
}

func TestBrowserLoginMinterRefreshesAndRotates(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "POST", r.Method)
		// The refresh token travels in the header, never the body.
		require.Equal(t, "refresh-1", r.Header.Get("X-Refresh-Token"))
		require.Equal(t, "SaaS", r.Header.Get("X-Product"))
		body, _ := io.ReadAll(r.Body)
		require.JSONEq(t, "{}", string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer srv.Close()

	cfg := &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}
	cache := New[string](Options{})
	headers, bErr := ResolveBearerFrom(context.Background(), cache, *cfg, srv.Client())
	require.Nil(t, bErr)
	require.Equal(t, "Bearer access-2", headers["Authorization"])
	require.EqualValues(t, 1, calls.Load())

	// A second call within the token's lifetime must not hit the network.
	_, bErr = ResolveBearerFrom(context.Background(), cache, *cfg, srv.Client())
	require.Nil(t, bErr)
	require.EqualValues(t, 1, calls.Load(), "warm token must not re-refresh")
}

func TestBrowserLoginMinterDeadRefreshTokenIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":12153,"msg":"refresh token expired"}`))
	}))
	defer srv.Close()

	cfg := &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("dead"),
	}
	_, bErr := ResolveBearerFrom(context.Background(), New[string](Options{}), *cfg, srv.Client())
	require.NotNil(t, bErr)
	require.NotNil(t, bErr.StatusCode, "a dead refresh token must be reported with a status")
	require.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
	require.NotNil(t, bErr.AllowFallbacks, "a dead credential must not fall back")
	require.False(t, *bErr.AllowFallbacks, "a dead credential must not fall back")
	require.Contains(t, bErr.Error.Message, "re-authenticate")
}

func TestBrowserLoginMinterRotateAndTiming(t *testing.T) {
	serve := func(t *testing.T, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Equal(t, "application/json", r.Header.Get("Accept"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("reports the rotated refresh token through onRotate", func(t *testing.T) {
		srv := serve(t, `{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		var gotAccess, gotRefresh string
		var gotExpiry time.Time
		mint := BrowserLoginMinter(cfg, srv.Client(), func(accessToken, refreshToken string, expiresAt time.Time) {
			gotAccess, gotRefresh, gotExpiry = accessToken, refreshToken, expiresAt
		})
		e, bErr := mint(context.Background(), nil)
		require.Nil(t, bErr)
		require.Equal(t, "access-2", e.Value)
		assert.Equal(t, "access-2", gotAccess)
		assert.Equal(t, "refresh-2", gotRefresh, "a rotated refresh token must reach the callback")
		assert.WithinDuration(t, e.ExpiresAt, gotExpiry, time.Second)
		// The cache must mint a minute before upstream expiry, not after it.
		assert.WithinDuration(t, time.Now().Add(time.Hour), e.ExpiresAt, 5*time.Second)
		assert.Equal(t, e.ExpiresAt.Add(-DefaultRefreshMargin), e.RefreshAt)
	})

	t.Run("a response without a rotated token keeps the original", func(t *testing.T) {
		srv := serve(t, `{"code":0,"data":{"accessToken":"access-2","expiresIn":3600}}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		var gotRefresh string
		mint := BrowserLoginMinter(cfg, srv.Client(), func(_, refreshToken string, _ time.Time) {
			gotRefresh = refreshToken
		})
		_, bErr := mint(context.Background(), nil)
		require.Nil(t, bErr)
		assert.Equal(t, "refresh-1", gotRefresh)
	})

	t.Run("a missing expires_in falls back to two minutes", func(t *testing.T) {
		// An unreported lifetime must not pin a token the endpoint considers dead.
		srv := serve(t, `{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2"}}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		e, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.Nil(t, bErr)
		assert.WithinDuration(t, time.Now().Add(2*time.Minute), e.ExpiresAt, 5*time.Second)
		assert.Equal(t, e.ExpiresAt.Add(-DefaultRefreshMargin), e.RefreshAt)
	})

	t.Run("a non-positive expires_in falls back to two minutes", func(t *testing.T) {
		srv := serve(t, `{"code":0,"data":{"accessToken":"access-2","expiresIn":-1}}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		e, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.Nil(t, bErr)
		assert.WithinDuration(t, time.Now().Add(2*time.Minute), e.ExpiresAt, 5*time.Second)
	})

	t.Run("an unknown refusal is transient, not a dead credential", func(t *testing.T) {
		// Only 401 and code 12153 mean the refresh token is gone. Anything else must leave
		// fallbacks open so a temporary endpoint fault does not take the lane down.
		srv := serve(t, `{"code":500,"msg":"upstream busy"}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		_, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.NotNil(t, bErr)
		require.NotNil(t, bErr.StatusCode)
		assert.Equal(t, http.StatusBadGateway, *bErr.StatusCode)
		assert.Nil(t, bErr.AllowFallbacks, "an unknown refusal must leave fallbacks open")
		assert.Contains(t, bErr.Error.Message, "upstream busy")
	})

	t.Run("a 2xx without an access token is not a success", func(t *testing.T) {
		srv := serve(t, `{"code":0,"data":{"refreshToken":"refresh-2"}}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		_, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.NotNil(t, bErr)
		assert.Contains(t, bErr.Error.Message, "no access_token")
	})

	t.Run("an expiry inside the refresh margin still yields a future RefreshAt", func(t *testing.T) {
		// A 30s lifetime is shorter than the 60s refresh margin: ExpiresAt-60s would land in
		// the past, making the entry stale on arrival. Every request would then serialise on
		// the slot mutex and hit the network — a refresh storm on the inference path.
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-short","refreshToken":"refresh-2","expiresIn":30}}`))
		}))
		t.Cleanup(srv.Close)
		cfg := schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		cache := New[string](Options{})
		headers, bErr := ResolveBearerFrom(context.Background(), cache, cfg, srv.Client())
		require.Nil(t, bErr)
		require.Equal(t, "Bearer access-short", headers["Authorization"])

		// A second call must be served from the cache, not a second refresh.
		_, bErr = ResolveBearerFrom(context.Background(), cache, cfg, srv.Client())
		require.Nil(t, bErr)
		require.EqualValues(t, 1, calls.Load(), "a short-lived token must not be re-minted on every call")

		// The entry itself must be fresh now and expire when the endpoint said it would.
		e, bErr := BrowserLoginMinter(&cfg, srv.Client(), nil)(context.Background(), nil)
		require.Nil(t, bErr)
		require.True(t, e.RefreshAt.After(time.Now()), "RefreshAt must be in the future for a short expiry")
		assert.WithinDuration(t, time.Now().Add(30*time.Second), e.ExpiresAt, 5*time.Second)
		assert.True(t, e.RefreshAt.Before(e.ExpiresAt), "RefreshAt must precede expiry")
	})

	t.Run("a 200 with the dead-token code is permanent on its own", func(t *testing.T) {
		// The code alone, with no HTTP 401, must be enough: the endpoint reports its real
		// status in the body envelope.
		srv := serve(t, `{"code":12153,"msg":"refresh token expired"}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("dead"),
		}
		_, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.NotNil(t, bErr)
		require.NotNil(t, bErr.StatusCode)
		assert.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
		require.NotNil(t, bErr.AllowFallbacks)
		assert.False(t, *bErr.AllowFallbacks, "a dead credential must not fall back")
		assert.Contains(t, bErr.Error.Message, "re-authenticate")
	})

	t.Run("a bare HTTP 401 without the code is permanent too", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(srv.Close)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("dead"),
		}
		_, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.NotNil(t, bErr)
		require.NotNil(t, bErr.StatusCode)
		assert.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
		require.NotNil(t, bErr.AllowFallbacks)
		assert.False(t, *bErr.AllowFallbacks)
		assert.Contains(t, bErr.Error.Message, "re-authenticate")
	})

	t.Run("a rejection never echoes the refresh token", func(t *testing.T) {
		srv := serve(t, `{"code":12153,"msg":"token refresh-1 is expired"}`)
		cfg := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(srv.URL),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
		_, bErr := BrowserLoginMinter(cfg, srv.Client(), nil)(context.Background(), nil)
		require.NotNil(t, bErr)
		assert.NotContains(t, bErr.Error.Message, "refresh-1")
	})
}

func TestBrowserLoginMinterConcurrentCallersRefreshOnce(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release // hold the first exchange open so the others pile up behind it
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-x","refreshToken":"refresh-x","expiresIn":3600}}`))
	}))
	defer srv.Close()
	cfg := schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("refresh-0"),
	}
	cache := New[string](Options{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ResolveBearerFrom(context.Background(), cache, cfg, srv.Client())
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	require.EqualValues(t, 1, calls.Load(), "concurrent callers must share one refresh")
}
