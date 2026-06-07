# Makefile for auth protobuf and sqlc code generation

IMAGE     := auth
SERVER    := root@upload.autre.cn
HTTP_PORT := 8087
GRPC_PORT := 50051

# 部署密钥从 gitignore 的 .env 读取（DATABASE_DSN / EMQX_AUTH_KEY）
-include .env

.PHONY: proto sqlc generate clean build build-image help deploy restart logs stop migrate run install-tools check-tools

# Default target
help:
	@echo "Available targets:"
	@echo "  proto      - Generate protobuf Go files"
	@echo "  sqlc       - Generate SQL code from queries"
	@echo "  generate   - Generate both proto and sqlc files"
	@echo "  clean      - Remove generated files"
	@echo "  build      - Build the combined server"
	@echo "  help       - Show this help message"

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@mkdir -p pkg/proto
	PATH=$$PATH:$(shell go env GOPATH)/bin protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       pkg/proto/auth.proto
	@echo "✅ Protobuf generation completed!"
	@echo "Generated files: proto/auth.pb.go, proto/auth_grpc.pb.go"

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

# Generate both proto and sqlc files
generate: proto sqlc
	@echo "✅ All code generation completed!"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -f proto/auth.pb.go proto/auth_grpc.pb.go
	@rm -rf db/*.go
	@echo "✅ Clean completed!"

# Install required tools (one-time setup)
install-tools:
	@echo "Installing required tools..."
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Installing sqlc..."
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@echo "✅ All tools installed! Make sure ~/.protoc/bin is in your PATH."

# Check if tools are installed
check-tools:
	@echo "Checking installed tools..."
	@command -v protoc >/dev/null 2>&1 && echo "✅ protoc found" || echo "❌ protoc not found"
	@command -v protoc-gen-go >/dev/null 2>&1 && echo "✅ protoc-gen-go found" || echo "❌ protoc-gen-go not found"
	@command -v protoc-gen-go-grpc >/dev/null 2>&1 && echo "✅ protoc-gen-go-grpc found" || echo "❌ protoc-gen-go-grpc not found"
	@command -v sqlc >/dev/null 2>&1 && echo "✅ sqlc found" || echo "❌ sqlc not found"

# Build combined server (main 位于仓库根目录 main.go)
build:
	@echo "Building combined HTTP/gRPC server..."
	go build -o bin/server .
	@echo "✅ Build completed! Binary: bin/server"

# Build docker image (由 deploy 目标调用)
# 从父目录构建，上下文包含 auth 与 gowk，满足 go.mod replace => ../gowk
build-image:
	@echo "Building docker image $(IMAGE):latest..."
	cd .. && docker build --platform linux/amd64 -f auth/Dockerfile -t $(IMAGE):latest .
	@echo "✅ Image built: $(IMAGE):latest"

# Run combined server（端口走环境变量 HTTP_SERVER_ADDR / GRPC_SERVER_ADDR）
run: build
	@echo "Starting combined HTTP/gRPC server..."
	./bin/server

## 构建 → 传输 → 服务器重启（一键部署）
deploy: build-image
	@echo ">>> 传输镜像到服务器..."
	docker save $(IMAGE) | ssh $(SERVER) "docker load"
	@echo ">>> 重启容器..."
	$(MAKE) restart

## 不重新构建，只重启服务器容器
restart:
	ssh $(SERVER) '\
		docker rm -f $(IMAGE) 2>/dev/null || true && \
		docker run -d \
			--name $(IMAGE) \
			--network docker_net \
			--network-alias $(IMAGE) \
			--restart always \
			-e HTTP_SERVER_ADDR=:$(HTTP_PORT) \
			-e GRPC_SERVER_ADDR=:$(GRPC_PORT) \
			-e DATABASE_DSN="$(DATABASE_DSN)" \
			-e REDIS_ADDR=redis:6379 \
			-e EMQX_AUTH_KEY=$(EMQX_AUTH_KEY) \
			$(IMAGE):latest \
	'
	@echo ">>> 容器已启动，查看日志:"
	$(MAKE) logs

## 查看服务器容器日志
logs:
	ssh $(SERVER) "docker logs --tail=50 $(IMAGE)"

## 停止并删除容器
stop:
	ssh $(SERVER) "docker rm -f $(IMAGE) || true"
