import base64
import hashlib
import os
import re
import json
import requests
import pickle
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import configparser
import shutil
import datetime
import urllib
import requests
from requests.adapters import HTTPAdapter

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

config = configparser.ConfigParser()
config.read("config.ini")

# Create a session object
s = requests.Session()

# Create an HTTP adapter with a maximum of 3 retries
adapter = HTTPAdapter(max_retries=10)

# Use the adapter as the session's transport adapter
s.mount("http://", adapter)
s.mount("https://", adapter)

# Set a default timeout for all requests made through the session
s.timeout = 30  # 30 seconds

client_id = config["DEFAULT"]["client_id"]
client_secret = config["DEFAULT"]["client_secret"]
redirect_uri = config["DEFAULT"]["redirect_uri"]

# Set the scopes
scopes = ["bookmark.read", "tweet.read", "users.read", "offline.access"]

# Check if the access token is cached
try:
    with open("access_token.pkl", "rb") as f:
        token = pickle.load(f)
    access = token["access_token"]
    
    # Check if the token has an expires_in field
    if "expires_in" in token:
        # Convert the expires_at field to a datetime object
        expires_at = datetime.datetime.fromtimestamp(
            token["expires_at"]
        )
        # Check if the current time is after the expires_at time
        if datetime.datetime.now() > expires_at:
            # The token has expired, check if we have a refresh token
            if "refresh_token" in token:
                # Use the refresh token to get a new access token
                refresh_url = "https://api.twitter.com/2/oauth2/token"
                auth = HTTPBasicAuth(client_id, client_secret)
                oauth = OAuth2Session(client_id, token=token)
                new_token = oauth.refresh_token(
                    refresh_url, auth=auth, client_id=client_id
                )
                # Update the token and save it to a file
                token.update(new_token)
                with open("access_token.pkl", "wb") as f:
                    pickle.dump(token, f)
                # Update the access token variable
                access = token["access_token"]
            else:
                # We don't have a refresh token, so we need to get a new access token
                raise ValueError("Token has expired and no refresh token available")
except (FileNotFoundError, EOFError, ValueError):
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
    
    # Save the token to a file
    with open("access_token.pkl", "wb") as f:
        pickle.dump(token, f)

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

# Create the downloads directory if it doesn't exist
downloads_dir = "downloads"
if not os.path.exists(downloads_dir):
    os.mkdir(downloads_dir)

def save_bookmarks(bookmarks, json_response):
    # Extract the users dictionary from the includes field
    users = json_response["includes"]["users"]

    # Iterate over the user's bookmarks
    for bookmark in bookmarks:
        # Get the author's id
        author_id = bookmark["author_id"]

        # Find the user with the matching id in the users dictionary
        user = next(user for user in users if user["id"] == author_id)
        # Get the username of the user
        author_screen_name = user["username"]

        # Create a folder for the author's bookmarks
        author_dir = os.path.join(downloads_dir, author_screen_name)
        os.makedirs(author_dir, exist_ok=True)

        # Create a folder for the bookmark
        bookmark_folder = os.path.join(author_dir, str(bookmark["id"]))
        os.makedirs(bookmark_folder, exist_ok=True)
        # Save the bookmark metadata to a file
        metadata_filename = os.path.join(bookmark_folder, "metadata.json")
        with open(metadata_filename, "w") as f:
            json.dump(bookmark, f, indent=2)

        # Save the text of the tweet as a .txt file
        tweet_text = bookmark["text"]
        tweet_file = open(os.path.join(bookmark_folder, "tweet.txt"), "w", encoding='utf-8')
        tweet_file.write(tweet_text)
        tweet_file.close()

        # Save any attached media to a format suitable to that media type
        media_keys = bookmark.get("attachments", {}).get("media_keys", [])
        for media_key in media_keys:
            # Find the media in the includes list
            media = next(m for m in json_response["includes"]["media"] if m["media_key"] == media_key)

            # Check if the media has a URL
            if "url" in media:
                # Save the media to a file with the appropriate extension
                media_url = media["url"]
                response = s.get(media_url)
                if response.status_code == 200:
                    media_filename = os.path.join(bookmark_folder, os.path.basename(media_url))
                    media_file = open(media_filename, "wb")
                    media_file.write(response.content)
                    media_file.close()
            elif "variants" in media:
                # Find the variant with the highest bit rate and save it to a file
                highest_bit_rate = 0
                highest_bit_rate_url = None
                for variant in media["variants"]:
                    bit_rate = variant.get("bit_rate", 0)
                    if bit_rate > highest_bit_rate:
                        highest_bit_rate = bit_rate
                        highest_bit_rate_url = variant.get("url")

                if highest_bit_rate_url:
                    # Save the media to a file with the appropriate extension
                    response = s.get(highest_bit_rate_url)
                    if response.status_code == 200:
                        # Parse the URL
                        parsed_url = urllib.parse.urlparse(highest_bit_rate_url)
                        # Parse the query string
                        query_string = urllib.parse.parse_qs(parsed_url.query)
                        # Remove the 'tag' parameter from the query string
                        query_string.pop("tag", None)
                        # Reassemble the URL with the modified query string
                        modified_url = urllib.parse.urlunparse(
                            (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, urllib.parse.urlencode(query_string, doseq=True), parsed_url.fragment)
                        )
                        # Split the file name into the base name and the extension
                        base_name, extension = os.path.splitext(os.path.basename(modified_url))
                        # Join the base name and the extension back together
                        media_filename = os.path.join(bookmark_folder, base_name + extension)
                        media_file = open(media_filename, "wb")
                        media_file.write(response.content)
                        media_file.close()



# Initialize variables to store the bookmarks and pagination token
bookmarks = []
pagination_token = None

while True:
    # Set the pagination token in the query parameters if it exists
    params = {}
    params["expansions"] = "author_id,attachments.media_keys"
    params["media.fields"] = "media_key,type,url,variants"
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

    # Save the bookmarks to the downloads directory
    save_bookmarks(json_response["data"], json_response)

    # Check if there are more pages of bookmarks
    try:
        next_token = json_response['meta']['next_token']
        pagination_token = next_token
    except KeyError:
        break
