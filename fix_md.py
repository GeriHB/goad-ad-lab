import os
import re

repo_path = "."  # Set this to your repository root
images_folder = "images"  # Your image folder in the repo root

# Regex to match Obsidian-style image links
obsidian_pattern = re.compile(r"!\[\[(Pasted image \d{14}\.png)\]\]")

for root, _, files in os.walk(repo_path):
    for file in files:
        if file.endswith(".md"):
            md_path = os.path.join(root, file)

            # Calculate relative path to "images" from the .md file's directory
            relative_path_to_root = os.path.relpath(repo_path, os.path.dirname(md_path))
            relative_images_path = os.path.join(relative_path_to_root, images_folder).replace("\\", "/")

            with open(md_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Replace Obsidian-style links with the correct relative path
            new_content = obsidian_pattern.sub(r"![](" + relative_images_path + r"/\1)", content)

            if new_content != content:
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated: {md_path}")

