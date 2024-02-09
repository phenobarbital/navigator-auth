import requests
from navconfig import config

USERNAME = config.get('MY_USERNAME')
PASSWORD = config.get('MY_PASSWORD')

URL = "http://nav-api.dev.local:5000"


def test_login_endpoint():
    # Endpoint URL
    url = URL + "/api/v1/login"
    # Credentials
    credentials = {
        "username": USERNAME,
        "password": PASSWORD
    }
    # Headers
    headers = {
        "x-auth-method": "BasicAuth"
    }
    # Sending POST request to the login endpoint
    response = requests.post(
        url,
        json=credentials,
        headers=headers
    )

    # Asserting that the response status code is 200 (OK)
    assert response.status_code == 200, "Failed to login, check endpoint or credentials"

    # Optionally, you can add more assertions here based on the expected response
    # For example, check if the response contains a specific key or message
    response_json = response.json()
    assert "token" in response_json, "Response does not contain authentication token"

# If you need to run more tests or use fixtures, you can add them below.
