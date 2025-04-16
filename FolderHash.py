import os 
import hashlib

def hash_files_in_directory(folderPath):
    """
    This function takes a directory path as input and returns a dictionary where the keys are the file names
    and the values are their respective SHA-256 hashes.
    """
    file_hashes = {}
    
    for root, dirs, files in os.walk(folderPath):
        for file in files:
            file_path = os.path.join(root, file)
            # Calculate SHA-256 hash of the file
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            # Store the hash in the dictionary
            file_hashes[file] = sha256_hash.hexdigest()
    
    return file_hashes

def hash_output(hashed_files):
    hash_list = []

    for file, file_hash in hashes.items():
            print(f"{file}: {file_hash}")
            hash_list.append(file_hash)            
    

    with open("hashedFiles.txt", 'w') as f:
        for hash in hash_list:
            f.write(f"{hash}\n")

if __name__ == "__main__":

    directory = input("Enter the directory path to hash files: ")
   
    if os.path.isdir(directory):
        hashes = hash_files_in_directory(directory)
    else:
        print("Invalid directory path.")

    hash_output(hashes)