package zns

import (
	"fmt"
	"net/http"
	"time"
)

var (
	ErrZNSDisabled        = fmt.Errorf("ZNS is disabled")
	ErrRefreshTokenNotSet = fmt.Errorf("refresh token is not set")
	ErrInvalidPhoneNumber = fmt.Errorf("invalid phone number")
	ErrAuthCodeNotFound   = fmt.Errorf("authentication code not found")
	ErrAccessTokenFailed  = fmt.Errorf("failed to get access token")
)

type TemplateType string

type Config struct {
	BaseURL       string `envconfig:"ZNS_BASE_URL"`
	AuthURL       string `envconfig:"ZNS_AUTH_URL"`
	AppID         string `envconfig:"ZNS_APP_ID"`
	SecretKey     string `envconfig:"ZNS_APP_SECRET"`
	CallbackURL   string `envconfig:"ZNS_CALLBACK_URL"`
	Enabled       bool   `envconfig:"ZNS_ENABLED" default:"false"`
	CodeVerifier  string `envconfig:"ZNS_CODE_VERIFIER"`
	CodeChallenge string `envconfig:"ZNS_CODE_CHALLENGE"`
	TemplateFile  string `envconfig:"ZNS_TEMPLATE_FILE"`
}

type Client struct {
	Config       Config
	accessToken  string
	refreshToken string
	expiredAt    time.Time
	httpClient   *http.Client
	errorHandler ErrorHandler
	template     map[string]string
}

type AuthHandler struct {
	auth *Client
}

type ErrorHandler func(err error)

type ClientOption func(*Client)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
}

type DataResponse struct {
	MsgID       string `json:"msg_id"`
	SentTime    string `json:"sent_time"`
	SendingMode string `json:"sending_mode"`
	Quota       Quota  `json:"quota"`
}

type Quota struct {
	DailyQuota     string `json:"daily_quota"`
	RemainingQuota string `json:"remaining_quota"`
}

type SendMessageInput struct {
	Data SendMessageData `json:"data"`
}

type SendMessageData struct {
	PhoneNumber  string                 `json:"phone_number"`
	TemplateType TemplateType           `json:"template_type"`
	TemplateData map[string]interface{} `json:"template_data"`
}

type Request struct {
	PhoneNumber  string                 `json:"phone"`
	TemplateID   string                 `json:"template_id"`
	TemplateData map[string]interface{} `json:"template_data"`
	TrackingID   string                 `json:"tracking_id"`
}

type Response struct {
	Error   int          `json:"error"`
	Message string       `json:"message"`
	Data    DataResponse `json:"data"`
}

type CallbackResponse struct {
	Error        *string    `json:"error,omitempty"`
	Message      string     `json:"message"`
	AccessToken  *string    `json:"access_token,omitempty"`
	RefreshToken *string    `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_in,omitempty"`
}
