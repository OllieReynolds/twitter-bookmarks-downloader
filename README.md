# twitter-bookmarks-downloader

- Simple script to download all Twitter bookmarks for your user
- Downloads rich media (photos/videos) attached to bookmarked tweets

## Prerequisites

1. Python 3.10.8
2. Twitter Developer API Account, setup with OAuth, associated with your Twitter account
3. Recommend creating a virtual environment

## Build and run

1. Create config.ini file based on the config.ini.example
2. Populate `client_id`, `client_secret` and `redirect_uri` in config.ini
3. Run: `pip install -r requirements.txt` to install the dependencies
4. Run the script: `python main.py`
