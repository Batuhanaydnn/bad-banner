
import requests 
from bs4 import BeautifulSoup
# intext:"gmail.com" shubham

def google_search_email(domain_name, search_name):

    search_engine_url = f"https://www.google.com/search?q=intext:{domain_name} {search_name}"

    try:
        response = requests.get(search_engine_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            results = soup.select('.g')

            for result in results:
                title = result.select_one('.r').get_text()
                link = result.select_one('a')['href']

                print(f"Title: {title}\nLink: {link}\n")
        else:
            print("An error occurred while processing the request.")
    except requests.exceptions.RequestException as man:
        print(f"An error occurred:  {str(man)}")

# The searchname field here can be duplicated according to the given string
searchname = "batuhanaydin"

domainname = "gmail.com"

print(google_search_email('gmail.com', 'batuhanaydn'))





# domain_name_list = [
#     'gmail.com',
#     'yahoo.com',
#     'hotmail.com',
#     'outlook.com'
# ]
