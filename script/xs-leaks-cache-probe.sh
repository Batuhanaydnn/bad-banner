#!/bin/bash

function ifCached() {
  local url=$1

  purgeUrl="${url}?purge=$(date +%s)"
  curl -s -o /dev/null -w "%{http_code}" -H "Cache-Control: no-cache" "$purgeUrl" > /dev/null

  cacheUrl="${url}?cache=$(date +%s)"
  curl -s -o /dev/null -w "%{http_code}" "$cacheUrl" > /dev/null

  errorUrl="${url}?error=$(date +%s)"
  errorResponse=$(curl -s -o /dev/null -w "%{http_code}" "$errorUrl")

  if [[ $errorResponse == "200" ]]; then
    echo "Kaynak önbelleğe alındı: $url"
  elif [[ $errorResponse == "0" ]]; then
    echo "CORS hatası: $url"
  else
    echo "Kaynak önbelleğe alınmadı: $url"
  fi
}

while read -r url; do
  ifCached "$url"
done < urls.txt