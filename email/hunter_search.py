# HUNTER EMAİL SEARCH v0.0.1
import requests

def hunter_email_search(email, api_key):
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"
    
    try:
        response = requests.get(url)
        status_code = response.status_code
        if status_code == 200:
            data = requests.json()
            if data['data']['status'] == 'deliverable':
                return f"The {email} provided is real (Yea man)"
            else:
                return f"The {email} it's definitely not real so ot could be but it's not no no it's not"
        else:
            return "The request you sent is completely wrong, maaan"
    except requests.exceptions.RequestException as man:
        return f"An error accurred: {str(man)}"
    
HUNTER_API_KEY = "your_api_key"

email_address = "info@batuhanaydn.com"

result = hunter_email_search(email_address, HUNTER_API_KEY)
print(result)