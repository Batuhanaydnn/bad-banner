import random
import time
from googlesearch import search
from bs4 import BeautifulSoup
import requests

def google_search_email(domain_name, search_name):
    for result in search(f'intext:{domain_name} {search_name}', num_results=10):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Referer": "https://www.google.com/"
        }
        dummy = 0
        try:
            delay = random.uniform(1, 3)
            time.sleep(delay)
            response = requests.get(result, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                title = soup.title.string
                print(f"{dummy}. search")
                print(f"Title: {title}\nLink: {result}\n")
                dummy += 1
            else:
                print(f"An error occurred while processing the request for {result}.")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {str(e)}")

domain_name = "gmail.com"
search_name = "batuhanaydin"
google_search_email(domain_name, search_name)