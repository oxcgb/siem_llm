#!/bin/sh
# AUTH_MODE=local: basic auth from SOC_USER/SOC_PASS
# AUTH_MODE=ad: no basic auth, sessions via backend
set -e

if [ "$AUTH_MODE" = "ad" ]; then
  sed -i \
    's/^\([[:space:]]*\)auth_basic /\1#auth_basic /; s/^\([[:space:]]*\)auth_basic_user_file /\1#auth_basic_user_file /' \
    /etc/nginx/templates/default.conf.template
  echo "[entrypoint] AUTH_MODE=ad: basic auth disabled"
elif [ -n "$SOC_USER" ] && [ -n "$SOC_PASS" ]; then
  HASH=$(openssl passwd -apr1 "$SOC_PASS")
  printf '%s:%s\n' "$SOC_USER" "$HASH" > /etc/nginx/.htpasswd
fi

exec /docker-entrypoint.sh nginx -g "daemon off;"
