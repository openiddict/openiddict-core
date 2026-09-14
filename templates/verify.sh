#!/usr/bin/env bash
# Packs the OpenIddict packages used by the templates into a temporary feed, instantiates
# each template, builds the generated projects and runs HTTP smoke tests against them.
#
# Requirements: bash, curl, openssl, python and a trusted ASP.NET Core development certificate.
# Usage: templates/verify.sh [work directory]
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK/feed" "$WORK/home" "$WORK/packages" "$WORK/out"

if [ -x "$REPO/.dotnet/dotnet" ] || [ -x "$REPO/.dotnet/dotnet.exe" ]; then
  export DOTNET_ROOT="$REPO/.dotnet"
  DN="$REPO/.dotnet/dotnet"
else
  DN="dotnet"
fi

export DOTNET_CLI_HOME="$WORK/home"
export NUGET_PACKAGES="$WORK/packages"
export DOTNET_NOLOGO=1
export ASPNETCORE_ENVIRONMENT=Development

FAILURES=0

check() { # name expected actual
  if [ "$2" == "$3" ]; then echo "  PASS $1"; else echo "  FAIL $1: expected $2, got $3"; FAILURES=$((FAILURES + 1)); fi
}

echo "== pack"
for p in OpenIddict.Abstractions OpenIddict.Core OpenIddict.Server OpenIddict.Server.AspNetCore OpenIddict.Server.AspNetCore.AdminUI \
         OpenIddict.EntityFrameworkCore.Models OpenIddict.EntityFrameworkCore OpenIddict.Client \
         OpenIddict.Client.AspNetCore OpenIddict.Client.SystemNetHttp OpenIddict.Client.AspNetCore.Bff; do
  "$DN" pack "$REPO/src/$p/$p.csproj" -o "$WORK/feed" > "$WORK/out/pack-$p.log" 2>&1 || { echo "  FAIL pack $p (see $WORK/out/pack-$p.log)"; exit 1; }
done

VERSION="$(ls "$WORK/feed" | sed -n 's/^OpenIddict\.Abstractions\.\(.*\)\.nupkg$/\1/p' | head -1)"
echo "  version $VERSION"

cat > "$WORK/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$WORK/feed" />
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF

cd "$WORK"

echo "== instantiate and build"
for t in Server.Identity:openiddict-server-identity:IdentityServer Server.Empty:openiddict-server-empty:EmptyServer Bff:openiddict-bff:BffHost; do
  IFS=: read -r folder name project <<< "$t"
  "$DN" new install "$REPO/templates/content/OpenIddict.$folder" > /dev/null 2>&1 || { echo "  FAIL install $name"; exit 1; }
  rm -rf "$project"
  "$DN" new "$name" -n "$project" --OpenIddictVersion "$VERSION" > /dev/null || { echo "  FAIL new $name"; exit 1; }
  if "$DN" build "$project/$project.csproj" > "$WORK/out/build-$project.log" 2>&1; then echo "  PASS build $name"; else echo "  FAIL build $name (see $WORK/out/build-$project.log)"; exit 1; fi
done

rm -rf IdentityAdminServer
"$DN" new openiddict-server-identity -n IdentityAdminServer --OpenIddictVersion "$VERSION" --admin-ui > /dev/null || { echo "  FAIL new openiddict-server-identity --admin-ui"; exit 1; }
if "$DN" build IdentityAdminServer/IdentityAdminServer.csproj > "$WORK/out/build-IdentityAdminServer.log" 2>&1; then echo "  PASS build openiddict-server-identity --admin-ui"; else echo "  FAIL build openiddict-server-identity --admin-ui (see $WORK/out/build-IdentityAdminServer.log)"; exit 1; fi

start() { # project port
  rm -f "$1"/*.sqlite3*
  (cd "$1" && "$DN" "bin/Debug/net10.0/$1.dll" --urls "https://127.0.0.1:$2" > "$WORK/out/run-$1.log" 2>&1 &)
  for _ in $(seq 1 60); do curl -sk -o /dev/null "https://127.0.0.1:$2/" && return; sleep 1; done
}

stop() { # port
  if command -v taskkill > /dev/null; then
    for pid in $(netstat -ano | grep "127.0.0.1:$1 .*LISTENING" | awk '{print $5}' | sort -u); do taskkill //F //PID "$pid" > /dev/null; done
  else
    fuser -k "$1/tcp" > /dev/null 2>&1
  fi
  sleep 1
}

status() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkdBjftJeZ4CVP"
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
QUERY="client_id=oidc-debugger&response_type=code&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug&scope=openid%20profile%20email&code_challenge=$CHALLENGE&code_challenge_method=S256"
json() { python -c "import json,sys;print(json.dumps(json.load(sys.stdin).get('$1')))"; }
redeem() { # base
  curl -sk --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=oidc-debugger" --data-urlencode "code=$CODE" \
    --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "redirect_uri=https://oidcdebugger.com/debug" "$1/connect/token" |
    python -c "import json,sys;print(json.load(sys.stdin).get('access_token',''))"
}

echo "== smoke openiddict-server-identity"
start IdentityServer 5198
B=https://127.0.0.1:5198; J="$WORK/identity.cookies"; rm -f "$J"
check discovery 200 "$(status "$B/.well-known/openid-configuration")"
check admin-api-disabled 404 "$(status "$B/openiddict/admin/applications")"
TOKEN=$(curl -sk -c "$J" -b "$J" "$B/Identity/Account/Register" | grep -o 'name="__RequestVerificationToken" type="hidden" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
check register 302 "$(status -c "$J" -b "$J" --data-urlencode "__RequestVerificationToken=$TOKEN" --data-urlencode "Input.Email=alice@example.com" \
  --data-urlencode "Input.Password=Passw0rd!Passw0rd" --data-urlencode "Input.ConfirmPassword=Passw0rd!Passw0rd" "$B/Identity/Account/Register")"
PAGE=$(curl -sk -c "$J" -b "$J" "$B/connect/authorize?$QUERY")
TOKEN=$(printf '%s' "$PAGE" | grep -o 'name="__RequestVerificationToken" type="hidden" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
check consent-form yes "$([ -n "$TOKEN" ] && echo yes || echo no)"
LOCATION=$(curl -sk -c "$J" -b "$J" -o /dev/null -w '%{redirect_url}' --data "$QUERY" --data-urlencode "__RequestVerificationToken=$TOKEN" --data-urlencode "submit.Accept=Yes" "$B/connect/authorize")
CODE=$(printf '%s' "$LOCATION" | grep -o 'code=[^&]*' | head -1 | cut -d= -f2)
check authorization-code yes "$([ -n "$CODE" ] && echo yes || echo no)"
ACCESS=$(redeem "$B")
check userinfo '"alice@example.com"' "$(curl -sk -H "Authorization: Bearer $ACCESS" "$B/connect/userinfo" | json email)"
stop 5198

echo "== smoke openiddict-server-identity --admin-ui"
start IdentityAdminServer 5195
check admin-ui-requires-authentication 302 "$(status "https://127.0.0.1:5195/admin/applications")"
stop 5195

echo "== smoke openiddict-server-empty"
start EmptyServer 5197
B=https://127.0.0.1:5197; J="$WORK/empty.cookies"; rm -f "$J"
AUTHZ="/connect/authorize?$QUERY"
check discovery 200 "$(status "$B/.well-known/openid-configuration")"
check authorize-challenge 302 "$(status -c "$J" -b "$J" "$B$AUTHZ")"
check prompt-none-login-required yes "$(curl -sk -o /dev/null -w '%{redirect_url}' "$B$AUTHZ&prompt=none" | grep -q 'error=login_required' && echo yes || echo no)"
TOKEN=$(curl -sk -c "$J" -b "$J" "$B/account/login" | grep -o 'name="__RequestVerificationToken" value="[^"]*"' | sed 's/.*value="//;s/"$//')
check login 302 "$(status -c "$J" -b "$J" --data-urlencode "__RequestVerificationToken=$TOKEN" --data-urlencode "UserName=alice" --data-urlencode "ReturnUrl=$AUTHZ" "$B/account/login")"
LOCATION=$(curl -sk -c "$J" -b "$J" -o /dev/null -w '%{redirect_url}' "$B$AUTHZ")
CODE=$(printf '%s' "$LOCATION" | grep -o 'code=[^&]*' | head -1 | cut -d= -f2)
check authorization-code yes "$([ -n "$CODE" ] && echo yes || echo no)"
ACCESS=$(redeem "$B")
check userinfo '"alice"' "$(curl -sk -H "Authorization: Bearer $ACCESS" "$B/connect/userinfo" | json sub)"
stop 5197

echo "== smoke openiddict-bff"
start BffHost 5196
B=https://127.0.0.1:5196
check index 200 "$(status "$B/")"
check user-anonymous 401 "$(status -H 'X-CSRF: 1' "$B/bff/user")"
check api-without-antiforgery-header 401 "$(status "$B/api/me")"
check api-anonymous 401 "$(status -H 'X-CSRF: 1' "$B/api/me")"
stop 5196

for t in Server.Identity Server.Empty Bff; do "$DN" new uninstall "$REPO/templates/content/OpenIddict.$t" > /dev/null 2>&1; done

echo "== $FAILURES failure(s)"
exit "$FAILURES"
