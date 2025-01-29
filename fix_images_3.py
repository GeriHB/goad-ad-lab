import os
import re

# Folder where your images are stored
image_folder = 'images'

# Function to update image references in markdown files
def update_md_references():
    # Loop through all image files in the 'images' folder
    for filename in os.listdir(image_folder):
        if filename.endswith('.png'):
            old_filepath = os.path.join(image_folder, filename)
            new_filename = filename.replace(' ', '_')  # Replace spaces with underscores
            new_filepath = os.path.join(image_folder, new_filename)

            # Rename the image file
            os.rename(old_filepath, new_filepath)
            print(f"Renamed: {filename} → {new_filename}")

            # Recursively go through all directories and update .md files
            for root, dirs, files in os.walk('.'):
                for md_file in files:
                    if md_file.endswith('.md'):
                        md_file_path = os.path.join(root, md_file)

                        # Open the markdown file and read its content
                        with open(md_file_path, 'r') as f:
                            content = f.read()

                        # Replace all old image references with the new ones
                        updated_content = content.replace(filename, new_filename)

                        # Write the updated content back to the markdown file
                        with open(md_file_path, 'w') as f:
                            f.write(updated_content)

                        print(f"Updated references in {md_file_path}")

if __name__ == "__main__":
    update_md_references()
    print("Done!")

