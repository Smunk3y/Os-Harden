#!/bin/bash

# Define a list of file extensions that you consider as media files
MEDIA_EXTENSIONS=("mp4" "mp3" "jpg" "png" "avi" "mkv" "pdf" "docx")

# Function to search for media files in a directory
search_media_files() {
  local dir="$1"
  for ext in "${MEDIA_EXTENSIONS[@]}"; do
    find "$dir" -type f -name "*.$ext"
  done
}

# Function to check user directories
check_user_directories() {
  local base_dir="/home"  # Change this to the base directory of user profiles
  local user_dirs=( "$base_dir"/* )
  
  for user_dir in "${user_dirs[@]}"; do
    if [ -d "$user_dir" ]; then
      echo "Checking media files for user: $(basename "$user_dir")"
      echo "--------------------------------------"
      search_media_files "$user_dir/Pictures"
      search_media_files "$user_dir/Documents"
      search_media_files "$user_dir/Videos"
      search_media_files "$user_dir/Music"
      search_media_files "$user_dir/Downloads"
      echo
    fi
  done
}

# Start the check
check_user_directories
