#!/bin/sh
sed -i "s|__VOUCH_ISSUER__|${VOUCH_ISSUER:-https://us.vouch.sh}|g" /usr/share/nginx/html/assets/*.js
sed -i "s|__VOUCH_CLIENT_ID__|${VOUCH_CLIENT_ID}|g" /usr/share/nginx/html/assets/*.js
sed -i "s|__VOUCH_REDIRECT_URI__|${VOUCH_REDIRECT_URI:-http://localhost:3000/callback}|g" /usr/share/nginx/html/assets/*.js
exec "$@"
