import os
import re

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

                # Replace spaces with underscores in the image paths
                updated_content = re.sub(r'(\!\[\]\(\.\./\.\./\.\./\.\./images/)([^)]+)(\.png\))', 
                                        lambda m: m.group(1) + m.group(2).replace(' ', '_') + m.group(3), content)

                # Write the updated content back to the markdown file
                if content != updated_content:
                    with open(md_file_path, 'w') as f:
                        f.write(updated_content)

                    print(f"Updated references in {md_file_path}")

if __name__ == "__main__":
    update_md_references()
    print("Done!")

