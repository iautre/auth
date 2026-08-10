package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// jsonOut 是各 tool 的统一输出：把 service 返回值序列化成 JSON 放入 data。
type jsonOut struct {
	Data json.RawMessage `json:"data" jsonschema:"接口返回 JSON"`
}

func wrap(v any) (jsonOut, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return jsonOut{}, fmt.Errorf("序列化失败: %w", err)
	}
	return jsonOut{Data: b}, nil
}

func (s *Server) oidcDiscovery(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, jsonOut, error) {
	out, err := wrap(service.DefaultOIDCService().GetDiscoveryDocument())
	return nil, out, err
}

func (s *Server) oidcJwks(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, jsonOut, error) {
	out, err := wrap(service.DefaultOIDCService().GetJwks(ctx))
	return nil, out, err
}

func (s *Server) userInfo(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, jsonOut, error) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		return nil, jsonOut{}, fmt.Errorf("未获取到登录身份")
	}
	var userService service.UserService
	user, err := userService.GetById(ctx, userID)
	if err != nil {
		return nil, jsonOut{}, err
	}
	out, err := wrap(dto.UserRes{
		Id:          user.ID,
		Phone:       user.Phone.String,
		Email:       user.Email.String,
		Nickname:    user.Nickname.String,
		Group:       user.Group.String,
		Avatar:      user.Avatar.String,
		IsVerified:  user.IsVerified.Bool,
		Enabled:     user.Enabled,
		LastLoginAt: user.LastLoginAt.Time.Format("2006-01-02T15:04:05Z"),
		Created:     user.Created.Time.Format("2006-01-02T15:04:05Z"),
	})
	return nil, out, err
}
