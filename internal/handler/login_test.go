package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

type testTokenStore struct {
	tokens sync.Map
}

func (s *testTokenStore) StoreToken(_ context.Context, key string, token *gowk.Token) error {
	s.tokens.Store(key, token)
	return nil
}

func (s *testTokenStore) LoadToken(_ context.Context, key string) (*gowk.Token, error) {
	value, ok := s.tokens.Load(key)
	if !ok {
		return nil, errors.New("token not found")
	}
	return value.(*gowk.Token), nil
}

func TestNativeLoginTokenIsAcceptedByCheckLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	loginRecorder := httptest.NewRecorder()
	loginCtx, _ := gin.CreateTestContext(loginRecorder)
	loginCtx.Request = httptest.NewRequest("POST", "/login", nil)
	token, err := gowk.Login(loginCtx, 42)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	checkRecorder := httptest.NewRecorder()
	checkCtx, _ := gin.CreateTestContext(checkRecorder)
	checkCtx.Request = httptest.NewRequest("GET", "/protected", nil)
	checkCtx.Request.Header.Set("Authorization", "Bearer "+token)
	gowk.CheckLogin(checkCtx)

	if got := gowk.LoginId(checkCtx); got != 42 {
		t.Fatalf("LoginId = %d, want 42", got)
	}
}
