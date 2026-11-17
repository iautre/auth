package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrChannelNotConfigured 表示对应的发送通道没有配置，接口应明确拒绝而不是假装发成功。
var ErrChannelNotConfigured = errors.New("该验证方式尚未配置发送通道")

// SMSSender 发送短信验证码。第三方接入时实现这个接口即可换成自己的短信商。
type SMSSender interface {
	SendCode(ctx context.Context, phone, code string) error
}

// Mailer 发送邮件验证码。
type Mailer interface {
	SendCode(ctx context.Context, email, code string) error
}

var (
	senderOnce sync.Once
	smsSender  SMSSender
	mailSender Mailer
)

// InitSenders 根据环境变量装配发送通道，幂等。
//
// SMS 走 AUTH_SMS_WEBHOOK：POST {"phone","code"} 到你自己的网关，
// auth 不内置任何厂商 SDK，避免包被第三方引用时带上一堆云厂商依赖。
// 邮件走标准 SMTP（AUTH_SMTP_ADDR / AUTH_SMTP_USERNAME / AUTH_SMTP_PASSWORD / AUTH_SMTP_FROM）。
func InitSenders() {
	senderOnce.Do(func() {
		if url := strings.TrimSpace(os.Getenv("AUTH_SMS_WEBHOOK")); url != "" {
			smsSender = &webhookSMS{
				url:   url,
				token: strings.TrimSpace(os.Getenv("AUTH_SMS_WEBHOOK_TOKEN")),
				client: &http.Client{
					Timeout: 10 * time.Second,
				},
			}
		} else {
			slog.Warn("auth sms: 未配置 AUTH_SMS_WEBHOOK，短信验证码将不可用")
		}

		m, err := newSMTPMailer()
		if err != nil {
			slog.Warn("auth mail: SMTP 配置无效，邮件验证码将不可用", "err", err)
		} else if m == nil {
			slog.Warn("auth mail: 未配置 SMTP，邮件验证码将不可用")
		} else {
			mailSender = m
		}
	})
}

func currentSMSSender() SMSSender { InitSenders(); return smsSender }
func currentMailer() Mailer       { InitSenders(); return mailSender }

// webhookSMS 把验证码 POST 给调用方自己的短信网关。
type webhookSMS struct {
	url    string
	token  string
	client *http.Client
}

func (w *webhookSMS) SendCode(ctx context.Context, phone, code string) error {
	payload, err := json.Marshal(map[string]string{"phone": phone, "code": code})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("调用短信网关失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("短信网关返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// smtpMailer 用标准库 SMTP 发验证码邮件，支持 STARTTLS。
type smtpMailer struct {
	addr     string
	host     string
	username string
	password string
	from     string
}

func newSMTPMailer() (Mailer, error) {
	addr := strings.TrimSpace(os.Getenv("AUTH_SMTP_ADDR"))
	if addr == "" {
		return nil, nil
	}
	from := strings.TrimSpace(os.Getenv("AUTH_SMTP_FROM"))
	if from == "" {
		return nil, errors.New("AUTH_SMTP_FROM 未配置")
	}

	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	return &smtpMailer{
		addr:     addr,
		host:     host,
		username: strings.TrimSpace(os.Getenv("AUTH_SMTP_USERNAME")),
		password: os.Getenv("AUTH_SMTP_PASSWORD"),
		from:     from,
	}, nil
}

func (m *smtpMailer) SendCode(ctx context.Context, email, code string) error {
	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}

	subject := "登录验证码"
	body := fmt.Sprintf("你的验证码是 %s，10 分钟内有效。如非本人操作请忽略本邮件。\r\n", code)
	msg := strings.Join([]string{
		"From: " + m.from,
		"To: " + email,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	// net/smtp 不支持 context，用 goroutine 兜住超时，避免请求线程被卡死。
	done := make(chan error, 1)
	go func() {
		done <- smtp.SendMail(m.addr, auth, m.from, []string{email}, []byte(msg))
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
