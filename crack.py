import zipfile
import string
import itertools

def extract_zip(zip_file, password):
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.extractall(pwd=password.encode())
            print(f"Successfully extracted with password: {password}")
            return True
    except:
        return False
def brute_force_zip(zip_file, max_len=8, charset=string.ascii_lowercase + string.digits):
    for length in range (1, max_len + 1):
        for guess in itertools.product(charset, repeat=length):
            password = ''.join(guess)
            if extract_zip(zip_file, password):
                return password
file_name = "Lostlife_v1.52_mod.zip"

candidate_password = ["hgames18s, hgamesI8s, hgamesl8s, hgames|8s"]
for pwd in candidate_password:
    if extract_zip(file_name, pwd):
        break
    else:
        print(f"Trying brute-force method...")
        found_password = brute_force_zip(file_name)
        if found_password:
            print(f"Password found: {found_password}")
        else:
            print("Password not found.")