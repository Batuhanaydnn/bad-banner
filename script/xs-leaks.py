import requests
import time
import random


def send_get_request(query):
    url = "https://example.com/search"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
    }
    params = {"query": query}
    response = requests.get(url, params=params, headers=headers)
    return response.text


def send_requests_with_delay(queries):
    for query in queries:
        result = send_get_request(query)
        print(f"Query: {query}, Result: {result}")
        delay = random.uniform(1, 5)
        time.sleep(delay)


def read_queries_from_file(file_path):
    with open(file_path, "r") as file:
        queries = file.read().splitlines()
    return queries


file_path = "queries.txt"
queries = read_queries_from_file(file_path)
send_requests_with_delay(queries)
