package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// consentCookiePrefix 拼上 client_id 作为"已同意该客户端"的标记。
// client_id 只含字母数字（动态注册生成），可直接安全用作 cookie 名。
const consentCookiePrefix = "oauth2_consent_"

// consentCookieMaxAge 是同意标记的有效期：同意一次，一个月内不再打扰。
const consentCookieMaxAge = 30 * 24 * 60 * 60

type consentPageData struct {
	ClientName string
	Scope      string
	ActionPath string
	Params     []consentParam
}

// consentParam 是授权确认页要回传的原始参数，避免确认后丢失 state / PKCE。
type consentParam struct {
	Name  string
	Value string
}

func consentCookieName(clientID string) string { return consentCookiePrefix + clientID }

func hasConsent(ctx *gin.Context, clientID string) bool {
	value, err := ctx.Cookie(consentCookieName(clientID))
	return err == nil && value == "1"
}

// grantConsent 记录"该客户端已获同意"。标记随浏览器会话存续，
// 不区分 scope：scope 变更时会重新询问。
func grantConsent(ctx *gin.Context, clientID string) {
	ctx.SetCookie(consentCookieName(clientID), "1", consentCookieMaxAge, "/", "", gowk.CookieSecure(), true)
}

// renderConsentPage 渲染授权确认页。只在参数全部校验通过后调用，
// 因此页面里的 redirect_uri 一定是该 client 登记过的地址。
func renderConsentPage(ctx *gin.Context, params *dto.OAuth2AuthRequest, client *service.AuthorizedClient) {
	setBrowserPageHeaders(ctx)
	data := consentPageData{
		ClientName: client.Name,
		Scope:      params.Scope,
		ActionPath: ctx.Request.URL.Path,
		Params: []consentParam{
			{Name: "response_type", Value: params.ResponseType},
			{Name: "client_id", Value: params.ClientID},
			{Name: "redirect_uri", Value: params.RedirectURI},
			{Name: "scope", Value: params.Scope},
			{Name: "state", Value: params.State},
			{Name: "nonce", Value: params.Nonce},
			{Name: "code_challenge", Value: params.CodeChallenge},
			{Name: "code_challenge_method", Value: params.CodeChallengeMethod},
			// resource 必须回传，否则用户在确认页点"允许"这一步就把
			// RFC 8707 的资源声明丢掉了。
			{Name: "resource", Value: params.Resource},
		},
	}
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "consent.html", data); err != nil {
		ctx.Error(err)
	}
}
