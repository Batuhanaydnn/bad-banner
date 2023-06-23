# FULLCONTACT EMAİL SEARCH v0.0.1
# Prepared by Muhammed Batuhan Aydın.
# Please issue an issue or contact me via info@batuhanaydn.com for development, ideas or requests.
import requests

def fullcontact_search_email(email, api_key):
    url = f"https://api.fullcontact.com/v3/person.enrichment.json?email={email}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Your App Name"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'status' in data and data['status'] == 200:
                if 'person' in data:
                    person_data = data['person']
                    return f"Email: {email}\nName: {person_data.get('name', 'N/A')}\nLocation: {person_data.get('location', {}).get('generalLocation', 'N/A')}"
                else:
                    return f"No information found for email: {email}"
            else:
                return f"An error occurred: {data.get('message', 'Unknown error')}"
        else:
            return "An error occurred while processing the request."
    except requests.exceptions.RequestException as man:
        return f"An error occurred: {str(man)}"

API_KEY = "your_fullcontact_api_key"

email_address = "info@batuhanaydn.com"

result = fullcontact_search_email(email_address, API_KEY)
print(result)