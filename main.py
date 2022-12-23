import os
import requests
import json

# Replace these with your own Twitter API keys and secrets
consumer_key = "YOUR_CONSUMER_KEY"
consumer_secret = "YOUR_CONSUMER_SECRET"
access_token = "YOUR_ACCESS_TOKEN"
access_token_secret = "YOUR_ACCESS_TOKEN_SECRET"

# Set up the authentication
auth = requests.auth.OAuth1(
    consumer_key, consumer_secret, access_token, access_token_secret
)

# Set up the base URL for the Twitter API
base_url = "https://api.twitter.com/1.1/bookmarks/list.json"

# Set up the parameters for the API request
params = {
    "count": 100,  # The number of bookmarks to retrieve (up to a maximum of 100)
    "full_text": "true",  # Include the full text of the tweet in the response
}

# Create the downloads directory if it doesn't exist
if not os.path.exists("downloads"):
    os.mkdir("downloads")

# Keep making API requests until we have retrieved all bookmarks
while True:
    # Make the API request
    response = requests.get(base_url, auth=auth, params=params)

    # Check the status code of the response
    if response.status_code == 200:
        # If the request was successful, parse the JSON data
        data = json.loads(response.text)
        bookmarks = data["bookmarks"]  # This is a list of bookmark objects

        # Iterate through the list of bookmarks
        for bookmark in bookmarks:
            tweet = bookmark["status"]  # This is a tweet object

            # Create a directory for this bookmark
            bookmark_dir = f"downloads/tweet_{tweet['id']}"
            os.mkdir(bookmark_dir)

            # Save the text of the tweet to a file
            with open(f"{bookmark_dir}/tweet.txt", "w") as f:
                f.write(tweet["text"])

            # Save any attached media to files
            media = tweet["entities"].get("media", [])
            for idx, m in enumerate(media):
                # Determine the file extension based on the media type
                media_type = m["type"]
                if media_type == "photo":
                    file_ext = "jpg"
                elif media_type == "video":
                    file_ext = "mp4"
                elif media_type == "animated_gif":
                    file_ext = "gif"
                else:
                    file_ext = "unknown"


                # Download the media and save it to a file
                media_url = m["media_url_https"]
                r = requests.get(media_url)
                with open(f"{bookmark_dir}/media_{idx}.{file_ext}", "wb") as f:
                    f.write(r.content)

        # Check
        if "next_cursor" in data and data["next_cursor"] != "0":
            # If there are more bookmarks, update the max_id parameter and make another request
            params["max_id"] = (
                data["bookmarks"][-1]["status"]["id"] - 1
            )  # Subtract 1 to avoid duplicates
        else:
            # If there are no more bookmarks, break out of the loop
            break
    else:
        # If the request was not successful, print the error message and break out of the loop
        print(f"Error: {response.text}")
        break
