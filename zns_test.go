package zns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	zeroLog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// Tests creating clients with different options
// Mock httpClient for testing
// ErrorHandler setup
// Template file loading

// Mock httpClient for testing
type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTripFunc != nil {
		return m.roundTripFunc(req)
	}
	return nil, nil
}

func newMockClient(roundTripFunc func(req *http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{
		Transport: &mockTransport{
			roundTripFunc: roundTripFunc,
		},
	}
}

func TestNewClient(t *testing.T) {
	config := Config{
		Enabled:   true,
		BaseURL:   "https://business.openapi.zalo.me/message/template",
		AuthURL:   "https://oauth.zaloapp.com/v4/oa/access_token",
		SecretKey: "test-secret-key",
		AppID:     "test-app-id",
	}

	t.Run("Create client with default options", func(t *testing.T) {
		client := NewClient(config)

		assert.Equal(t, config, client.Config)
		assert.Nil(t, client.httpClient)
		assert.Nil(t, client.errorHandler)
	})

	t.Run("Create client with custom http client", func(t *testing.T) {
		httpClient := http.Client{
			Timeout: 30 * time.Second,
		}

		client := NewClient(config, WithHttpClient(&httpClient))
		assert.Equal(t, &httpClient, client.httpClient)
	})

	t.Run("Create client with nil http client", func(t *testing.T) {
		client := NewClient(config, WithHttpClient(nil))

		assert.NotNil(t, client.httpClient)
		assert.Equal(t, 30*time.Second, client.httpClient.Timeout)
	})

	t.Run("Create client with custom error handler", func(t *testing.T) {
		var capturedError error
		errorHandler := func(err error) {
			capturedError = err
		}

		client := NewClient(config, WithErrorHandler(errorHandler))
		testError := fmt.Errorf("test error")

		client.errorHandler(testError)
		assert.Equal(t, testError, capturedError)
	})

	t.Run("Create client with template file", func(t *testing.T) {
		configTemplate := config
		configTemplate.TemplateFile = "test_template.json"
		client := NewClient(configTemplate)
		assert.Equal(t, "test_template.json", client.Config.TemplateFile)
	})
}

func TestIsEnabled(t *testing.T) {
	t.Run("Check if client is enabled", func(t *testing.T) {
		config := Config{
			Enabled: true,
		}
		client := NewClient(config)

		assert.True(t, client.Config.Enabled, "Client should be enabled")
	})

	t.Run("Check if client is disabled", func(t *testing.T) {
		config := Config{
			Enabled: false,
		}
		client := NewClient(config)

		assert.False(t, client.Config.Enabled, "Client should be disabled")
	})
}

func TestGetAccessToken(t *testing.T) {
	config := Config{
		Enabled:   true,
		AuthURL:   "https://oauth.zaloapp.com/v4/oa/access_token",
		AppID:     "test-app-id",
		SecretKey: "test-secret-key",
	}

	t.Run("successfully get access token", func(t *testing.T) {
		mockResponse := TokenResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresIn:    "3600",
		}

		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", req.Method)
			assert.Equal(t, config.AuthURL, req.URL.String())
			assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
			assert.Equal(t, config.SecretKey, req.Header.Get("secret_key"))

			body, _ := io.ReadAll(req.Body)
			values, _ := url.ParseQuery(string(body))
			assert.Equal(t, "authorization_code", values.Get("grant_type"))
			assert.Equal(t, "test_auth_code", values.Get("code"))
			assert.Equal(t, "test_code_verifier", values.Get("code_verifier"))
			assert.Equal(t, config.AppID, values.Get("app_id"))

			responseBody, _ := json.Marshal(mockResponse)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient))

		tokenResp, err := client.GetAccessToken("test_auth_code", "test_code_verifier")
		assert.NoError(t, err)
		assert.Equal(t, mockResponse.AccessToken, tokenResp.AccessToken)
		assert.Equal(t, mockResponse.RefreshToken, tokenResp.RefreshToken)
		assert.Equal(t, mockResponse.ExpiresIn, tokenResp.ExpiresIn)

		// verify client state after getting access token
		assert.Equal(t, mockResponse.AccessToken, client.accessToken)
		assert.Equal(t, mockResponse.RefreshToken, client.refreshToken)
		assert.True(t, client.expiredAt.After(time.Now()))
	})

	t.Run("http request error", func(t *testing.T) {
		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString("Bad Request")),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient), WithErrorHandler(func(err error) {}))

		tokenResp, err := client.GetAccessToken("test_auth_code", "test_code_verifier")
		assert.Error(t, err)
		assert.Nil(t, tokenResp)
		assert.Contains(t, err.Error(), "status_code: 400")
	})

	t.Run("disabled client", func(t *testing.T) {
		config.Enabled = false
		client := NewClient(config, WithErrorHandler(func(err error) {}))

		_, err := client.GetAccessToken("test_auth_code", "test_code_verifier")
		assert.Error(t, err)
		assert.Equal(t, ErrZNSDisabled, err)
	})
}

func TestRefreshAccessToken(t *testing.T) {
	config := Config{
		Enabled:   true,
		AuthURL:   "https://oauth.zaloapp.com/v4/oa/access_token",
		AppID:     "test-app-id",
		SecretKey: "test-secret-key",
	}
	t.Run("successfully refresh access token", func(t *testing.T) {
		mockResponse := TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    "3600",
		}

		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", req.Method)
			assert.Equal(t, config.AuthURL, req.URL.String())
			assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
			assert.Equal(t, config.SecretKey, req.Header.Get("secret_key"))

			body, _ := io.ReadAll(req.Body)
			values, _ := url.ParseQuery(string(body))
			assert.Equal(t, "refresh_token", values.Get("grant_type"))
			assert.Equal(t, "test-refresh-token", values.Get("refresh_token"))
			assert.Equal(t, config.AppID, values.Get("app_id"))

			responseBody, _ := json.Marshal(mockResponse)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient))
		client.refreshToken = "test-refresh-token"
		err := client.RefreshAccessToken()

		assert.NoError(t, err)
		assert.Equal(t, mockResponse.AccessToken, client.accessToken)
		assert.Equal(t, mockResponse.RefreshToken, client.refreshToken)
		assert.True(t, client.expiredAt.After(time.Now()))
	})

	t.Run("refresh token not set", func(t *testing.T) {
		client := NewClient(config, WithErrorHandler(func(err error) {}))

		err := client.RefreshAccessToken()
		assert.Error(t, err)
		assert.Equal(t, ErrRefreshTokenNotSet, err)
	})
}

func TestSetRefreshToken(t *testing.T) {
	config := Config{Enabled: true}
	t.Run("set refresh token successfully", func(t *testing.T) {
		client := NewClient(config)
		err := client.SetRefreshToken("new-refresh-token")

		assert.NoError(t, err)
		assert.Equal(t, "new-refresh-token", client.refreshToken)
	})
}

func TestSendNotification(t *testing.T) {
	config := Config{
		Enabled: true,
		BaseURL: "https://business.openapi.zalo.me/message/template",
	}
	templateData := map[string]interface{}{
		"phone":       "84987654321",
		"template_id": "7895417a7d3f9461cd2e",
		"template_data": map[string]interface{}{
			"ky":         "1",
			"thang":      "4/2020",
			"start_date": "20/03/2020",
			"end_date":   "20/04/2020",
			"customer":   "Nguyễn Thị Hoàng Anh",
			"cid":        "PE010299485",
			"address":    "VNG Campus, TP.HCM",
			"amount":     "100",
			"total":      "100000",
		},
		"tracking_id": "tracking_id",
	}

	t.Run("successfully send notification", func(t *testing.T) {
		mockResponse := Response{
			Error:   0,
			Message: "Success",
			Data: DataResponse{
				MsgID:       "msg123",
				SentTime:    "1626926349402",
				SendingMode: "1",
				Quota:       Quota{DailyQuota: "500", RemainingQuota: "499"},
			},
		}

		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", req.Method)
			assert.Equal(t, config.BaseURL, req.URL.String())
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, config.SecretKey, req.Header.Get("secret_key"))

			body, _ := io.ReadAll(req.Body)
			var requestBody map[string]interface{}
			json.Unmarshal(body, &requestBody)

			assert.NotEmpty(t, requestBody["phone"])
			assert.NotEmpty(t, requestBody["template_id"])
			assert.NotEmpty(t, requestBody["template_data"])

			responseBody, _ := json.Marshal(mockResponse)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient))
		client.accessToken = "test-access-token"
		client.expiredAt = time.Now().Add(1 * time.Hour)

		response, err := client.SendNotification("0123456789", "template123", templateData)
		assert.NoError(t, err)
		assert.Equal(t, mockResponse.Error, response.Error)
		assert.Equal(t, mockResponse.Message, response.Message)
		assert.Equal(t, mockResponse.Data.MsgID, response.Data.MsgID)
		assert.Equal(t, mockResponse.Data.SentTime, response.Data.SentTime)
		assert.Equal(t, mockResponse.Data.SendingMode, response.Data.SendingMode)
		assert.Equal(t, mockResponse.Data.Quota.DailyQuota, response.Data.Quota.DailyQuota)
		assert.Equal(t, mockResponse.Data.Quota.RemainingQuota, response.Data.Quota.RemainingQuota)
	})

	t.Run("API error response", func(t *testing.T) {
		mockResponse := Response{
			Error:   1,
			Message: "Error sending notification",
			Data:    DataResponse{},
		}

		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			responseBody, _ := json.Marshal(mockResponse)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient), WithErrorHandler(func(err error) {
			zeroLog.Error().Err(err).Msg("Error sending notification")
		}))

		client.accessToken = "test-access-token"
		client.expiredAt = time.Now().Add(1 * time.Hour)

		_, err := client.SendNotification("invalid-phone", "template123", templateData)
		assert.Error(t, err)
	})

	t.Run("disabled client", func(t *testing.T) {
		config.Enabled = false
		client := NewClient(config, WithErrorHandler(func(err error) {}))

		_, err := client.SendNotification("0123456789", "template123", nil)
		assert.Error(t, err)
		assert.Equal(t, ErrZNSDisabled, err)
	})
}

func TestAuthHandler_HandleCallBack(t *testing.T) {
	config := Config{
		Enabled:   true,
		BaseURL:   "https://business.openapi.zalo.me/message/template",
		AuthURL:   "https://oauth.zaloapp.com/v4/oa/access_token",
		SecretKey: "test-secret-key",
		AppID:     "test-app-id",
	}

	t.Run("successfully handle callback", func(t *testing.T) {
		mockResponse := TokenResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresIn:    "3600",
		}

		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {

			responseBody, _ := json.Marshal(mockResponse)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient))
		authHandler := NewAuthHandler(client)

		c, w := MockGinContext()
		c.Request = httptest.NewRequest("GET", "/callback?code=test_auth_code&state=test_state", nil)

		authHandler.HandleCallback(c)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("error missing parameters", func(t *testing.T) {
		client := NewClient(config)

		authHandler := NewAuthHandler(client)

		c, w := MockGinContext()
		c.Request = httptest.NewRequest("GET", "/callback", nil)
		authHandler.HandleCallback(c)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("error getting access token", func(t *testing.T) {
		mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("Internal Server Error")),
			}, nil
		})

		client := NewClient(config, WithHttpClient(mockClient), WithErrorHandler(func(err error) {
			zeroLog.Error().Err(err).Msg("Error getting access token")
		}))

		authHandler := NewAuthHandler(client)

		c, w := MockGinContext()
		c.Request = httptest.NewRequest("GET", "/callback?code=test_auth_code&state=test_state", nil)

		authHandler.HandleCallback(c)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestFormatPhoneNumber(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"0123456789", "84123456789"},
		{"84123456789", "84123456789"},
		{"01234567890", "841234567890"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("format %s", tc.input), func(t *testing.T) {
			result := formatPhoneNumber(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func MockGinContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}
