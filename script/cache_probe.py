import requests


def if_cached(url):
    purge_url = f"{url}?purge"
    requests.get(purge_url, headers={"Cache-Control": "no-cache"})

    cache_url = f"{url}?cache"
    cache_response = requests.get(cache_url)

    error_url = f"{url}?error"
    error_response = requests.get(error_url)

    if cache_response.status_code == 200:
        print(f"Resource cached: {url}")
    elif error_response.status_code == 0:
        print(f"CORS hatası: {url}")
    else:
        print(f"Resource not cached: {url}")


with open("urls.txt", "r") as file:
    for line in file:
        url = line.strip()
        if_cached(url)
