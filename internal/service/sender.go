package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"strings"
	"sync"
)

// ErrChannelNotConfigured 表示发信通道没有配置，接口应明确拒绝而不是假装发成功。
var ErrChannelNotConfigured = errors.New("该验证方式尚未配置发送通道")

// Mailer 发送邮箱验证码。
type Mailer interface {
	SendCode(ctx context.Context, email, code string) error
}

var (
	senderOnce sync.Once
	mailSender Mailer
)

// InitMailer 根据环境变量装配发信通道，幂等。
// 邮件走标准 SMTP（AUTH_SMTP_ADDR / AUTH_SMTP_USERNAME / AUTH_SMTP_PASSWORD / AUTH_SMTP_FROM）。
func InitMailer() {
	senderOnce.Do(func() {
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

func currentMailer() Mailer { InitMailer(); return mailSender }

// smtpMailer 用标准库 SMTP 发验证码邮件。
// 加密方式按端口自动选择：465 是隐式 TLS（SMTPS，连上即握手），其余端口走 STARTTLS。
type smtpMailer struct {
	addr        string
	host        string
	username    string
	password    string
	from        string
	implicitTLS bool
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
		// 465 是 SMTPS：TCP 连上就是 TLS，没有明文问候与 STARTTLS 升级。
		implicitTLS: strings.HasSuffix(addr, ":465"),
	}, nil
}

func (m *smtpMailer) SendCode(ctx context.Context, email, code string) error {
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
		if m.implicitTLS {
			done <- m.sendImplicitTLS(email, []byte(msg))
			return
		}
		var auth smtp.Auth
		if m.username != "" {
			auth = smtp.PlainAuth("", m.username, m.password, m.host)
		}
		done <- smtp.SendMail(m.addr, auth, m.from, []string{email}, []byte(msg))
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendImplicitTLS 走 465 那种「连上即 TLS」的会话。
// 不能用 smtp.SendMail：它按明文连接建立，再靠 STARTTLS 升级，465 不提供该指令。
func (m *smtpMailer) sendImplicitTLS(to string, msg []byte) error {
	conn, err := tls.Dial("tcp", m.addr, &tls.Config{
		ServerName: m.host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("连接 SMTP（隐式 TLS）失败: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer c.Close()

	if m.username != "" {
		// 不用 smtp.PlainAuth：它会检查 ServerInfo.TLS，而 NewClient 并不知道底层
		// conn 已被 tls.Dial 加密，会直接拒绝发密码。连接本身已加密，这里只需发 AUTH。
		if err := c.Auth(&implicitPlainAuth{username: m.username, password: m.password}); err != nil {
			return err
		}
	}
	if err := c.Mail(m.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// implicitPlainAuth 是 AUTH PLAIN 的实现，专门用于已由调用方加密的连接。
type implicitPlainAuth struct {
	username string
	password string
}

func (a *implicitPlainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a *implicitPlainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("smtp: 服务器要求额外的认证交互，AUTH PLAIN 不应出现")
	}
	return nil, nil
}
