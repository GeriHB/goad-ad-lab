import os
import re

# Folder where your images are stored
image_folder = 'images'

# Function to rename image files and update references in markdown files
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

            # Update all markdown files
            for md_file in os.listdir('.'):
                if md_file.endswith('.md'):
                    with open(md_file, 'r') as f:
                        content = f.read()

                    # Replace the old image reference with the new one
                    updated_content = content.replace(filename, new_filename)

                    with open(md_file, 'w') as f:
                        f.write(updated_content)

                    print(f"Updated references in {md_file}")

if __name__ == "__main__":
    update_md_references()
    print("Done!")

