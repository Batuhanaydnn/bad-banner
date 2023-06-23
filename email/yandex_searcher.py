import random
import time
from yandex_search import YandexSearch


def yandex_search_email(domain_name, search_name):
    api_key = "<your_api_key_here>"
    ys = YandexSearch(api_user=api_key, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    search_engine_query = f"intext:{domain_name} {search_name}"
    try:
        delay = random.uniform(1, 3)
        time.sleep(delay)
        results = ys.search(search_engine_query)['items']
        for result in results:
            title = result['title']
            link = result['url']
            print(f"Title: {title}\nLink: {link}\n")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

domain_name = "attack.com"
search_name = "attacker"
yandex_search_email(domain_name, search_name)