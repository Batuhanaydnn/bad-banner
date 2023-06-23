# CLEARBIT EMAİL SEARCH v0.0.1
# Prepared by Muhammed Batuhan Aydın.
# Please issue an issue or contact me via info@batuhanaydn.com for development, ideas or requests.

import requests

def clearbit_email_search(email, api_key):
    url = f"https://person.clearbit.com/v2/combined/find?email={email}"
    headers = {
        "Authorization" : f"Bearer {api_key}",
        "User-Agent" : "Bad-Banner"
    }

    try:
        response = requests.get(url, headers=headers)
        status_code = response.status_code
        if status_code == 200:
    
            data = response.json()
            if 'person' in data:
                person_data = data['person']

                return f"Email: {email}\nName: {person_data.get('name', {}).get('fullName', 'N/A')}\nLocation: {person_data.get('location', {}).get('locality', 'N/A')}"
            else:
                return f"No information found for {email}"
        else:
            return "The request you sent is completely wrong, maaan"
    except requests.exceptions.RequestException as man:
        return f"An error occurred: {str(man)}"
    
API_KEY = "your_clearbit_api_key"

email_address = "info@batuhanaydn.com"

result = clearbit_email_search(email_address, API_KEY)
print(result)
