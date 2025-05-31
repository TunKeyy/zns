package zns

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	zeroLog "github.com/rs/zerolog/log"
)

func NewClient(config Config, opts ...ClientOption) *Client {
	client := &Client{
		Config: config,
	}

	for _, opt := range opts {
		opt(client)
	}

	if config.TemplateFile != "" {
		client.template = getTemplateFilePath(config.TemplateFile)
	}

	return client
}

func defaultErrorHandler(err error) {
	if err != nil {
		zeroLog.Error().Err(err).Fields(map[string]interface{}{
			"type": "zns",
		}).Msg(err.Error())
	}
}

func WithHttpClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient == nil {
			c.httpClient = &http.Client{
				Timeout: 30 * time.Second,
			}
		} else {
			c.httpClient = httpClient
		}
	}
}

func WithErrorHandler(handler ErrorHandler) ClientOption {
	return func(c *Client) {
		if handler == nil {
			c.errorHandler = defaultErrorHandler
		} else {
			c.errorHandler = handler
		}
	}
}

func (c *Client) IsEnabled() bool {
	return c.Config.Enabled
}

func (c *Client) GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (c *Client) GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (c *Client) GetAccessToken(authorizationCode, codeVerifier string) (*TokenResponse, error) {
	if !c.IsEnabled() {
		c.errorHandler(ErrZNSDisabled)
		return nil, ErrZNSDisabled
	}

	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"code_verifier": {codeVerifier},
	}

	if c.Config.AppID != "" {
		v.Set("app_id", c.Config.AppID)
	}

	req, err := http.NewRequest("POST", c.Config.AuthURL, strings.NewReader(v.Encode()))
	if err != nil {
		c.errorHandler(err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("secret_key", c.Config.SecretKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.errorHandler(err)
		return nil, fmt.Errorf("fail to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("fail to fetch %s, status_code: %d", c.Config.AuthURL, resp.StatusCode)
		c.errorHandler(err)
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Error parsing data %s", err.Error())
		return nil, err
	}

	var tokenResp TokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		c.errorHandler(err)
		return nil, err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	expiresIn, err := strconv.Atoi(tokenResp.ExpiresIn)
	if err != nil {
		c.errorHandler(err)
		return nil, err
	}
	c.expiredAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return &tokenResp, nil
}

func (c *Client) RefreshAccessToken() error {
	if !c.IsEnabled() {
		c.errorHandler(ErrZNSDisabled)
		return ErrZNSDisabled
	}

	if c.refreshToken == "" {
		c.errorHandler(ErrRefreshTokenNotSet)
		return ErrRefreshTokenNotSet
	}

	v := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
	}

	if c.Config.AppID != "" {
		v.Set("app_id", c.Config.AppID)
	}

	req, err := http.NewRequest("POST", c.Config.AuthURL, strings.NewReader(v.Encode()))
	if err != nil {
		c.errorHandler(err)
		return fmt.Errorf("fail to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("secret_key", c.Config.SecretKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.errorHandler(err)
		return fmt.Errorf("fail to send request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("fail to fetch %s, status_code: %d", c.Config.AuthURL, resp.StatusCode)
		c.errorHandler(err)
		return err
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Error parsing data %s", err.Error())
		return err
	}

	var tokenResp TokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		c.errorHandler(err)
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken

	expiresIn, err := strconv.Atoi(tokenResp.ExpiresIn)
	if err != nil {
		return err
	}
	c.expiredAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return nil
}

func (c *Client) ensureAccessToken() error {
	if !c.IsEnabled() {
		c.errorHandler(ErrZNSDisabled)
		return ErrZNSDisabled
	}

	if c.accessToken == "" || time.Now().After(c.expiredAt) {
		return c.RefreshAccessToken()
	}

	return nil
}

func (c *Client) SetRefreshToken(refreshToken string) error {
	if !c.IsEnabled() {
		c.errorHandler(ErrZNSDisabled)
		return ErrZNSDisabled
	}

	c.refreshToken = refreshToken
	return nil
}

func (c *Client) SendNotification(phoneNumber, templateID string, templateData map[string]interface{}) (*Response, error) {
	if !c.IsEnabled() {
		c.errorHandler(ErrZNSDisabled)
		return nil, ErrZNSDisabled
	}

	if err := c.ensureAccessToken(); err != nil {
		return nil, err
	}

	formattedPhoneNumber := formatPhoneNumber(phoneNumber)

	newTrackingID := strings.Replace(uuid.New().String(), "-", "", -1)
	requestBoby := Request{
		PhoneNumber:  formattedPhoneNumber,
		TemplateID:   templateID,
		TemplateData: templateData,
		TrackingID:   newTrackingID,
	}

	jsonData, err := json.Marshal(requestBoby)
	if err != nil {
		c.errorHandler(fmt.Errorf("fail to marshal request body: %v", err))
		return nil, err
	}

	req, err := http.NewRequest("POST", c.Config.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.errorHandler(fmt.Errorf("fail to create notification request: %v", err))
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("access_token", c.accessToken)

	resp, err := c.httpClient.Do(req)

	if err != nil {
		c.errorHandler(fmt.Errorf("fail to send notification: %v", err))
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		c.errorHandler(err)
		return nil, fmt.Errorf("fail to read response body: %v", err)
	}

	var znsResp Response
	if err = json.Unmarshal(body, &znsResp); err != nil {
		c.errorHandler(err)
		return nil, fmt.Errorf("fail to unmarshal response: %v", err)
	}

	if znsResp.Error != 0 {
		err := fmt.Errorf("ZNS error: %d, message: %s", znsResp.Error, znsResp.Message)
		c.errorHandler(err)
		return nil, err
	}

	return &znsResp, nil
}

func NewAuthHandler(auth *Client) *AuthHandler {
	return &AuthHandler{
		auth: auth,
	}
}

func (c *AuthHandler) HandleCallback(ctx *gin.Context) {
	code := ctx.Query("code")

	if code == "" {
		ctx.JSON(http.StatusBadRequest, CallbackResponse{
			Error:   getPtr("authorization_code_required"),
			Message: "Authorization code is required",
		})

		return
	}

	_, err := c.auth.GetAccessToken(code, c.auth.Config.CodeVerifier)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, CallbackResponse{
			Error:   getPtr("token_fetch_error"),
			Message: fmt.Sprintf("Failed to fetch access token: %v", err),
		})

		return
	}

	ctx.JSON(http.StatusOK, CallbackResponse{
		Message:      "Authentication successful",
		AccessToken:  &c.auth.accessToken,
		RefreshToken: &c.auth.refreshToken,
		ExpiresAt:    &c.auth.expiredAt,
	})
}

func formatPhoneNumber(phoneNumber string) string {
	if !strings.HasPrefix(phoneNumber, "84") {
		phoneNumber = "84" + phoneNumber[1:]
	}

	return phoneNumber
}
