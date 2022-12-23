import base64
import hashlib
import os
import re
import json
import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import configparser

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

config = configparser.ConfigParser()
config.read("config.ini")

client_id = config["DEFAULT"]["client_id"]
client_secret = config["DEFAULT"]["client_secret"]
redirect_uri = config["DEFAULT"]["redirect_uri"]

# Set the scopes
scopes = ["bookmark.read", "tweet.read", "users.read", "offline.access"]

# Create a code verifier
code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

# Create a code challenge
code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

# Start an OAuth 2.0 session
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

# Create an authorize URL
auth_url = "https://twitter.com/i/oauth2/authorize"
authorization_url, state = oauth.authorization_url(
    auth_url, code_challenge=code_challenge, code_challenge_method="S256"
)

# Visit the URL to authorize your App to make requests on behalf of a user
print(
    "Visit the following URL to authorize your App on behalf of your Twitter handle in a browser:"
)
print(authorization_url)

# Paste in your authorize URL to complete the request
authorization_response = input(
    "Paste in the full URL after you've authorized your App:\n"
)

# Fetch your access token
token_url = "https://api.twitter.com/2/oauth2/token"

auth = HTTPBasicAuth(client_id, client_secret)

token = oauth.fetch_token(
    token_url=token_url,
    authorization_response=authorization_response,
    auth=auth,
    client_id=client_id,
    include_client_id=True,
    code_verifier=code_verifier,
)

# Your access token
access = token["access_token"]

# Make a request to the users/me endpoint to get your user ID
user_me = requests.request(
    "GET",
    "https://api.twitter.com/2/users/me",
    headers={"Authorization": "Bearer {}".format(access)},
).json()
user_id = user_me["data"]["id"]

# Make a request to the bookmarks url
url = "https://api.twitter.com/2/users/{}/bookmarks".format(user_id)
headers = {
    "Authorization": "Bearer {}".format(access),
    "User-Agent": "BookmarksSampleCode",
}

# Initialize variables to store the bookmarks and pagination token
bookmarks = []
pagination_token = None

while True:
    # Set the pagination token in the query parameters if it exists
    params = {}
    if pagination_token:
        params["pagination_token"] = pagination_token

    # Make the request
    response = requests.request("GET", url, headers=headers, params=params)
    if response.status_code != 200:
        raise Exception(
            "Request returned an error: {} {}".format(response.status_code, response.text)
        )
    print("Response code: {}".format(response.status_code))
    json_response = response.json()

    # Append the bookmarks from the response to the list of bookmarks
    bookmarks += json_response["data"]

    # Get the pagination token from the response
    pagination_token = json_response.get("pagination_token")

    # If the pagination token is None, it means we have reached the last page of bookmarks
    if pagination_token is None:
        break

print(bookmarks)

