FROM golang:1.26.4-alpine as go-builder

# 父级上下文构建：auth 依赖本地 gowk（go.mod replace => ../gowk）
COPY auth /app/auth
COPY gowk /app/gowk

WORKDIR /app/auth

RUN set -x \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update && apk --no-cache add tzdata git

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GOPROXY=https://goproxy.io,direct

RUN rm -f go.work go.work.sum && go work init && go work use . ../gowk \
    && go build -ldflags "-s -w" -o server . && chmod +x server

# production stage
FROM scratch

ENV GIN_MODE=release
ENV GO_ENV=prod
# 端口默认值（部署可由 docker run -e 覆盖）；gowk 直接读取这两个环境变量。
ENV HTTP_SERVER_ADDR=:8087
ENV GRPC_SERVER_ADDR=:50051

COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=go-builder /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
COPY --from=go-builder /app/auth/server /

# 健康检查：scratch 无 shell/curl，复用二进制自带的 healthcheck 子命令探测 /health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/server", "healthcheck"]

ENTRYPOINT ["/server"]
