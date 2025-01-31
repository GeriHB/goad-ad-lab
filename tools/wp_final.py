import requests
import csv
import os
from datetime import datetime
from html import unescape

def fetch_wordpress_posts(base_url, start_date, end_date):
    endpoint = f"{base_url}/wp-json/wp/v2/posts"
    params = {
        'after': f"{start_date}T00:00:00",
        'before': f"{end_date}T23:59:59",
        'per_page': 100
    }

    all_posts = []
    try:
        while endpoint:
            response = requests.get(endpoint, params=params)
            if response.status_code != 200:
                raise Exception(f"Error fetching posts: {response.status_code}")

            posts = response.json()
            all_posts.extend(posts)

            # Check if there is a next page
            if 'next' in response.links:
                endpoint = response.links['next']['url']
                params = None  # `params` are only for the initial request
            else:
                break

    except Exception as e:
        print(f"An error occurred: {e}")

    return all_posts

def analyze_and_save_posts(posts, end_date):
    authors = {}

    for post in posts:
        author_id = post['author']
        title = unescape(post['title']['rendered'])
        link = post['link']
        date = post['date']

        if author_id not in authors:
            authors[author_id] = []

        authors[author_id].append({
            'title': title,
            'link': link,
            'date': date
        })

    # Save posts per author in files
    os.makedirs("wordpress_posts", exist_ok=True)

    for author_id, posts in authors.items():
        author_name = f"Author {author_id}"
        filename = f"wordpress_posts/{author_name}_{end_date}.csv"
        with open(filename, "w", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Post Number", "Author", "Title", "Link", "Date"])
            for idx, post in enumerate(posts, start=1):
                writer.writerow([idx, author_name, post['title'], post['link'], post['date']])

        print(f"Saved {len(posts)} posts for {author_name} in {filename}")

def main():
    base_url = "https://rks.news"
    start_date = input("Enter start date (YYYY-MM-DD): ")
    end_date = input("Enter end date (YYYY-MM-DD): ")

    try:
        # Validate date format
        datetime.strptime(start_date, "%Y-%m-%d")
        datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        print("Invalid date format. Please use YYYY-MM-DD.")
        return

    try:
        print("Fetching WordPress posts...")
        posts = fetch_wordpress_posts(base_url, start_date, end_date)

        if posts:
            print(f"Fetched {len(posts)} posts.")
            print("Analyzing and saving posts...")
            analyze_and_save_posts(posts, end_date)
        else:
            print("No posts found in the given period.")
    except Exception as e:
        print(f"An error occurred during processing: {e}")

if __name__ == "__main__":
    main()

