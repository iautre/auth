# Makefile for auth sqlc code generation and deployment

IMAGE     := auth
REGISTRY  := docker.cnb.cool/autre
IMG       := $(REGISTRY)/$(IMAGE)
HTTP_PORT := 8087

# 部署环境从 gitignore 的 .env 读取（BASE_URL / DATABASE_DSN / EMQX_AUTH_KEY / DEPLOY_HOST）
-include .env

# 部署目标机不在仓库里写死，取自 .env 的 DEPLOY_HOST（形如 user@host）
SERVER ?= $(DEPLOY_HOST)

# 构建运行时：有 container(Apple) 用 container，否则 docker
RUNTIME := $(shell command -v container >/dev/null 2>&1 && echo container || echo docker)
ifeq ($(RUNTIME),container)
PUSH := container image push
else
PUSH := docker push
endif

.PHONY: sqlc generate clean build build-image push cnb-build help deploy restart logs stop migrate run install-tools check-tools check-server

# Default target
help:
	@echo "Available targets:"
	@echo "  sqlc       - Generate SQL code from queries"
	@echo "  clean      - Remove generated files"
	@echo "  build      - Build the server"
	@echo "  help       - Show this help message"

# Generate SQL code from queries
sqlc:
	@echo "Generating SQL code..."
	@if ! command -v sqlc >/dev/null 2>&1; then \
		echo "❌ sqlc not found. Install with: go install github.com/kyleconroy/sqlc/cmd/sqlc@latest"; \
		exit 1; \
	fi
	sqlc generate
	@echo "✅ SQL code generation completed!"
	@echo "Generated files in db/ directory"

# Generate SQL code
generate: sqlc
	@echo "✅ All code generation completed!"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf db/*.go
	@echo "✅ Clean completed!"

# Install required tools (one-time setup)
install-tools:
	@echo "Installing required tools..."
	@echo "Installing sqlc..."
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@echo "✅ All tools installed!"

# Check if tools are installed
check-tools:
	@echo "Checking installed tools..."
	@command -v sqlc >/dev/null 2>&1 && echo "✅ sqlc found" || echo "❌ sqlc not found"

# 构建版本：注入到 gowk.Version（默认 beta），用 git tag/commit 覆盖
VERSION := $(shell git describe --tags --always 2>/dev/null || echo beta)
LDFLAGS := -X github.com/iautre/gowk.Version=$(VERSION)

# Build server (main 位于仓库根目录 main.go)
build:
	@echo "Building HTTP server (version=$(VERSION))..."
	go build -ldflags "$(LDFLAGS)" -o bin/server .
	@echo "✅ Build completed! Binary: bin/server"

# Build docker image (由 deploy 目标调用)
# 上下文为 auth 自身目录，gowk 按 go.mod 远程拉取（无本地 replace）
# 有 container(Apple) 用 container，否则 docker
build-image:
	@echo "Building image $(IMG):latest (runtime=$(RUNTIME), version=$(VERSION))..."
	$(RUNTIME) build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t $(IMG):latest .
	@echo "✅ Image built: $(IMG):latest"

# 推送镜像到 cnb（需先登录：$(RUNTIME) [registry] login docker.cnb.cool -u cnb -p <令牌>）
push:
	$(PUSH) $(IMG):latest

# 本地触发 CNB 云端构建（双架构 amd64+arm64）并等待完成，再交给 restart 拉取部署。
# CNB_BUILD_TOKEN 在 .env 配置（个人访问令牌，需 repo-cnb-trigger:rw 权限）。
cnb-build:
	@test -n "$(CNB_BUILD_TOKEN)" || { echo "❌ 请设置环境变量 CNB_BUILD_TOKEN"; exit 1; }
	@bash scripts/cnb-build.sh

# Run server（端口走环境变量 HTTP_SERVER_ADDR）
run: build
	@echo "Starting HTTP server..."
	./bin/server

## 部署目标机未配置时直接报错，避免 ssh 到空地址
check-server:
	@test -n "$(SERVER)" || { echo "❌ DEPLOY_HOST 未设置：在 .env 里加一行 DEPLOY_HOST=user@host"; exit 1; }

## 触发 CNB 云端构建（双架构）→ 等待成功 → 服务器拉取并重启（一键部署）
deploy: cnb-build restart

## 服务器拉取最新镜像并重启容器（私有仓库需服务器先 docker login docker.cnb.cool）
## 敏感项（AUTH_ENCRYPTION_KEY / AUTH_SMTP_*）不放命令行走 shell，改由服务器上的
## env-file 注入：docker --env-file 逐行读取、不做变量展开，密码里的 $ 等字符原样保留。
restart: check-server
	ssh $(SERVER) '\
		docker pull $(IMG):latest && \
		docker rm -f $(IMAGE) 2>/dev/null; \
		docker run -d \
			--name $(IMAGE) \
			--network docker_net \
			--network-alias $(IMAGE) \
			--restart always \
			--env-file /app/docker/auth/auth.env \
			-e HTTP_SERVER_ADDR=:$(HTTP_PORT) \
			-e BASE_URL=$(BASE_URL) \
			-e DATABASE_DSN="$(DATABASE_DSN)" \
			-e REDIS_ADDR=redis:6379 \
			-e EMQX_AUTH_KEY=$(EMQX_AUTH_KEY) \
			-e EMQX_DEVICE_CREDENTIALS="$(EMQX_DEVICE_CREDENTIALS)" \
			$(IMG):latest \
	'
	@echo ">>> 容器已启动，查看日志:"
	$(MAKE) logs

## 查看服务器容器日志
logs: check-server
	ssh $(SERVER) "docker logs --tail=50 $(IMAGE)"

## 停止并删除容器
stop: check-server
	ssh $(SERVER) "docker rm -f $(IMAGE) || true"
