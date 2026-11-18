#!/usr/bin/env bash
# 本地触发 CNB 云端构建（api_trigger，amd64+arm64），轮询直到构建结束。
# 依赖：CNB_BUILD_TOKEN（有 repo-cnb-trigger:rw 权限的个人访问令牌，由 Makefile 从 .env 注入）
set -euo pipefail

REPO="autre/auth"
EVENT="api_trigger"
BRANCH="main"
API="https://api.cnb.cool/${REPO}/-/build"
TIMEOUT_SEC=900      # 15 分钟
INTERVAL_SEC=5

: "${CNB_BUILD_TOKEN:?请先在 .env 配置 CNB_BUILD_TOKEN}"

json_get() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null || true; }

# 1. 触发构建 -> sn + 日志链接
# 用 config 参数把本地 .cnb.yml 内容随请求传给 CNB，无需远端仓库预置该文件。
payload=$(python3 -c "
import json
print(json.dumps({'event':'${EVENT}','branch':'${BRANCH}','config':open('.cnb.yml').read()}))
")
resp=$(curl -sS -X POST "${API}/start" \
  -H "Accept: application/vnd.cnb.api+json" \
  -H "Authorization: ${CNB_BUILD_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$payload")
sn=$(printf '%s' "$resp" | json_get "['sn']")
log_url=$(printf '%s' "$resp" | json_get "['buildLogUrl']")
if [ -z "$sn" ] || [ "$sn" = "None" ]; then
  echo "触发构建失败：$resp" >&2
  exit 1
fi
echo "已触发构建：sn=${sn}"
[ -n "$log_url" ] && [ "$log_url" != "None" ] && echo "构建日志：${log_url}"

# 2. 轮询状态直到结束
deadline=$(( $(date +%s) + TIMEOUT_SEC ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  st=$(curl -sS "${API}/status/${sn}" \
    -H "Accept: application/vnd.cnb.api+json" \
    -H "Authorization: ${CNB_BUILD_TOKEN}" | json_get "['status']")
  st_lc=$(printf '%s' "$st" | tr '[:upper:]' '[:lower:]')
  case "$st_lc" in
    success|succeeded)
      echo "构建成功：${sn}"
      exit 0
      ;;
    *fail*|*error*|*cancel*|*abort*|*stop*|*terminat*)
      echo "构建失败：${sn}（status=${st}）" >&2
      [ -n "$log_url" ] && echo "构建日志：${log_url}" >&2
      exit 1
      ;;
    *)
      echo "构建中… status=${st:-unknown}"
      sleep "$INTERVAL_SEC"
      ;;
  esac
done

echo "构建超时（${TIMEOUT_SEC}s）：${sn}" >&2
[ -n "$log_url" ] && echo "构建日志：${log_url}" >&2
exit 1
