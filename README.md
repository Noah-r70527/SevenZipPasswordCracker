# SevenZipCracker

This module provides a simple way to perform a **dictionary attack** against an encrypted 7zip archive using Python.  
It leverages a password list file to attempt each password until the correct one is found.

## Features
- Uses a password list (e.g., `rockyou.txt`) for dictionary-based password cracking.  
- Parallelized using Python’s `multiprocessing` for faster attempts.  
- Stops as soon as the correct password is discovered.  
- Extracts contents of the 7zip archive into a target directory upon success.  
- Displays attempt counts and time taken.  


## Usage

### 1. Prepare your files
- The encrypted `.7z` file you want to crack  
- A `.txt` wordlist file containing potential passwords (e.g., `rockyou.txt`)  
- An output directory where files will be extracted if the password is found  

### 2. Example Code

```python
from SevenZipCracker import SevenZipCracker

archive_path = "test.7z"
password_file = "rockyou.txt"
output_dir = "output"

cracker = SevenZipCracker(
    file_to_crack=archive_path,
    password_list_file=password_file,
    output_dir=output_dir
)

cracker.execute_crack()
