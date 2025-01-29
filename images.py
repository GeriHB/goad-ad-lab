import os
import re

# Folder where your images are stored
image_folder = 'images'

# Function to update image references in markdown files
def update_md_references():
    # Walk through all directories and files recursively
    for root, dirs, files in os.walk('.'):
        for md_file in files:
            if md_file.endswith('.md'):
                md_file_path = os.path.join(root, md_file)

                # Open the markdown file and read its content
                with open(md_file_path, 'r') as f:
                    content = f.read()

                # Regular expression to match image links with relative paths
                updated_content = re.sub(r'(\!\[\]\(\.\./\.\./\.\./\.\./\.\./)([^)]+)(\.png\))',
                                        lambda m: f'![]({image_folder}/{m.group(2)})', content)

                # Write the updated content back to the markdown file
                if content != updated_content:
                    with open(md_file_path, 'w') as f:
                        f.write(updated_content)

                    print(f"Updated references in {md_file_path}")

if __name__ == "__main__":
    update_md_references()
    print("Done!")

