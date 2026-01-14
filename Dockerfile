FROM golang:1.25.5-alpine3.22 as go-builder

WORKDIR /app
COPY . /app

RUN set -x \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update && apk upgrade\
    && apk --no-cache add tzdata upx git \
    # && apk --no-cache add tzdata \
    && go env -w GO111MODULE=on \
    && go env -w GOPROXY=https://goproxy.io,direct \
    && go env -w CGO_ENABLED=0 \
    && go env -w GOOS=linux

RUN set -x \
    && ls -la \
    ## -ldflags "-s -w"进新压缩
    && go build -ldflags "-s -w" -o server_temp \
    ## 借助第三方工具再压缩压缩级别为-1-9
    && upx -9 server_temp -o server \
    # && cp server_temp server \
    && rm -f server_temp

# production stage
FROM scratch as production

ENV GO_ENV=prod
ENV GIN_MODE=release
ENV HTTP_SERVER_ADDR=8020
ENV GRPC_SERVER_ADDR=80201

COPY --from=go-builder /app/server /
COPY --from=go-builder /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

EXPOSE 8020
ENTRYPOINT ["/server"]
