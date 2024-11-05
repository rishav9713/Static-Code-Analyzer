import zipfile
import os
import glob

def extract_zip(zip_path, extract_to='extracted_files'):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    
    return extract_to

def get_all_files(directory):
    return [f for f in glob.glob(directory + "/**/*", recursive=True) if os.path.isfile(f)]
