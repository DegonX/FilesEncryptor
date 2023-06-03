import os
import base64
import random
import string
import subprocess
import ctypes
import tempfile
import cv2
import numpy as np
import tkinter as tk
import io
from PIL import Image, ImageTk

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from hashlib import sha256

success, unaffected, dire = 0, 0, 0
vlc_path = 'C:/Program Files/VideoLAN/VLC/vlc.exe'
vlc_path2 = 'C:/Program Files (x86)/VideoLAN/VLC/vlc.exe'


# put all files you want to encryption or decryption in a folder name 'files' in the same path as the project

def encrypt_files(path, password):
    global success, unaffected, dire
    files_list = os.listdir(path)

    # Iterate over the files in the given path
    for file_name in files_list:
        if file_name[0] != '.' and not os.path.isdir(path + file_name):
            if len(file_name) <= 80:
                # Read the file data
                data = open(path + file_name, 'rb').read()

                # Generate a random salt
                salt = os.urandom(16)

                # Derive the encryption key using the provided password and salt
                kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
                key = base64.urlsafe_b64encode(kdf.derive(password))

                # Create a Fernet cipher instance with the derived key
                fernet = Fernet(key)

                # Encrypt the file data
                encrypted_data = fernet.encrypt(data)

                # Write the salt and encrypted data to the file
                file = open(path + file_name, 'wb')
                file.write(salt + encrypted_data)
                file.close()

                # Encrypt the file name and encode it
                name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).encrypt(file_name.encode()).decode()

                # Rename the file with the encrypted file name
                os.rename(path + file_name, path + '.' + name)

                success += 1
            else:
                unaffected += 1
                print("File name is too long. Please change it to a shorter name with less than 80 characters.")
                print(f"\n{file_name}")
        elif os.path.isdir(path + file_name):
            dire += 1
            # Recursively encrypt files in subdirectories
            encrypt_files(path + file_name + '/', password)
        else:
            unaffected += 1
        print(f"{success + unaffected} files done.")


def decrypt_files(path, password):
    global success, unaffected, dire
    files_list = os.listdir(path)
    for file_name in files_list:
        if file_name[0] == '.' and not os.path.isdir(path + file_name):
            try:
                # Read the encrypted data from the file
                data = open(path + file_name, 'rb').read()

                # Extract the salt and encrypted data
                salt = data[:16]
                encrypted_data = data[16:]

                # Derive the encryption key using the provided password and salt
                kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
                key = base64.urlsafe_b64encode(kdf.derive(password))

                # Create a Fernet cipher instance with the derived key
                fernet = Fernet(key)

                # Decrypt the encrypted data
                decrypted_data = fernet.decrypt(encrypted_data)

                # Write the decrypted data back to the file
                file = open(path + file_name, 'wb')
                file.write(decrypted_data)
                file.close()

                try:
                    # Decrypt the file name and decode it
                    name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).decrypt(
                        file_name[1:].encode()).decode()
                    success += 1
                except cryptography.fernet.InvalidToken:
                    # If the file name decryption fails, generate a random name
                    name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                    print(f"File name is corrupted, the format is unknown. The file name will be changed to {name}")
                    success += 1

                # Rename the file with the decrypted file name
                os.rename(path + file_name, path + name)
                print(f"{success + unaffected} files done.")
            except cryptography.fernet.InvalidToken:
                unaffected += 1
                print(f"{success + unaffected}. Wrong password")

        elif os.path.isdir(path + file_name):
            dire += 1
            # Recursively decrypt files in subdirectories
            decrypt_files(path + file_name + '/', password)
        else:
            unaffected += 1
            print(f"{success + unaffected} files done.")


# create "Locker" folder, put the files you want to hide in it.

def lock_folder():
    # Locks the folder by renaming it and setting attributes
    os.system("ren locker \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
    os.system("C:\\Windows\\System32\\attrib +h +s \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
    print("Folder locked")


def unlock_folder():
    # Unlocks the folder by entering the correct password
    password = input("Enter password: ")
    if password == "bjffg7":
        os.system("C:\\Windows\\System32\\attrib -h -s \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
        os.system("ren \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\" locker")
        print("Folder unlocked successfully")
    else:
        print("Invalid password")


def create_folder():
    # Creates a new folder named "locker"
    os.mkdir("locker")
    print("Locker created successfully")


def setfileslist(path, password):
    print('\n\n\n\n\n')
    incorrectpasswordcount = 0
    fileslist = []
    dirlist = []
    files_list = os.listdir(path)

    # Iterate over the files in the given path
    for file_name in files_list:
        try:
            if file_name[0] == '.' and not os.path.isdir(os.path.join(path, file_name)):
                # Decrypt the encrypted file name using the provided password
                name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).decrypt(
                    file_name[1:].encode()).decode()
                if name.endswith(('.mp4', '.jpg', 'png', '.gif', '.txt')):
                    fileslist.append([name, file_name])  # Store the decrypted file name and the original file name
            elif os.path.isdir(os.path.join(path, file_name)):
                dirlist.append(file_name)  # Store the directory name
        except cryptography.fernet.InvalidToken:
            incorrectpasswordcount += 1  # Count the files for which the password is incorrect

    if incorrectpasswordcount > 0:
        print(f"wrong password for {incorrectpasswordcount} files ")

    print(f'\n{path}\n')
    print("enter number to select video or change folder")
    print("enter -1 to return to the previous folder or 0 to return to main menu")

    index = 0

    if len(fileslist) > 0:
        print("\nfiles list:")
        for file in fileslist:
            index += 1
            print(f"{index}.{file[0]}")

    if len(dirlist) > 0:
        print("\nfolders list:")
        for dirname in dirlist:
            index += 1
            print(f"{index}.{dirname}")

    print('\n')

    sel = 999
    while sel != 0:
        try:
            sel = int(input('enter number : '))
            if 0 < sel <= index:
                if sel <= len(fileslist):
                    decrypted_data = decryptfile(path, fileslist[sel - 1], password)
                    if fileslist[sel - 1][0].endswith('.mp4'):
                        playvideo(decrypted_data)
                    elif fileslist[sel - 1][0].endswith(('.jpg', '.png')):
                        showimage(decrypted_data)
                    elif fileslist[sel - 1][0].endswith('.gif'):
                        playgif(decrypted_data)
                    elif fileslist[sel - 1][0].endswith('.txt'):
                        showtext(decrypted_data)
                else:
                    setfileslist(os.path.join(path, dirlist[sel - len(fileslist) - 1]), password)
                    sel = 0
            elif sel == -1:
                if path != './files':
                    sel = 0
                    setfileslist(os.path.dirname(path), password)
                else:
                    print("cannot move out of this folder.")
            elif sel > index or sel < -1:
                print("invalid number.")
        except ValueError:
            print("invalid input, numbers only.")


def decryptfile(path, file, password):
    # Read the encrypted file data
    data = open(os.path.join(path, file[1]), 'rb').read()

    # Extract the salt and encrypted data from the file data
    salt = data[:16]
    encrypted_data = data[16:]

    # Derive the encryption key from the provided password and salt
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # Create a Fernet cipher using the derived key
    fernet = Fernet(key)

    # Decrypt the encrypted data using the Fernet cipher
    decrypted_data = fernet.decrypt(encrypted_data)

    # Return the decrypted data
    return decrypted_data


# temp file will be created in 'AppData\Local\Temp', temp file will be deleted after vlc player closed
def playvideo(decrypted_data):
    # Check if vlc_path exists, otherwise use vlc_path2
    if os.path.exists(vlc_path):
        player_path = vlc_path
    else:
        player_path = vlc_path2

    # Create a temporary file with the .mp4 extension
    with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmpfile:
        # Write the decrypted data to the temporary file
        tmpfile.write(decrypted_data)

    # Get the path of the temporary file
    file_path = tmpfile.name

    # Start the VLC player process
    vlc_process = subprocess.Popen([player_path, file_path])

    # Wait for the VLC player process to finish
    while vlc_process.poll() is None:
        pass

    # Check the exit status of the VLC player process
    if vlc_process.poll() == 0:
        # Close the temporary file and remove it
        tmpfile.close()
        os.remove(file_path)


def playgif(decrypted_data):
    # Create a BytesIO object from the decrypted_data
    gif_file = io.BytesIO(decrypted_data)

    # Open the GIF image using PIL's Image module
    gif_image = Image.open(gif_file)

    # Create a Tkinter window
    window = tk.Tk()

    # Create a label to display the GIF frames
    label = tk.Label(window)
    label.pack()

    # Initialize an empty list to store the frames
    frames = []

    try:
        # Read the frames of the GIF in a loop until an EOFError is encountered
        while True:
            # Append each frame to the frames list
            frames.append(gif_image.copy())
            gif_image.seek(len(frames))
    except EOFError:
        pass

    def update_frame(index):
        # Get the frame at the given index
        frame = frames[index]

        # Create a PhotoImage from the frame using Tkinter's ImageTk module
        tk_image = ImageTk.PhotoImage(frame)

        # Update the label's image with the new frame
        label.config(image=tk_image)
        label.image = tk_image

        # Schedule the next frame update after the duration specified in the GIF's metadata
        window.after(gif_image.info['duration'], update_frame, (index + 1) % len(frames))

    # Start the GIF animation by updating the first frame
    update_frame(0)

    # Enter the Tkinter event loop
    window.mainloop()


def showimage(decrypted_data):
    # Convert the decrypted_data (bytes) to a numpy array
    nparr = np.frombuffer(decrypted_data, np.uint8)

    # Decode the image using OpenCV
    decoded_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    # Get the screen width and height
    user32 = ctypes.windll.user32
    screen_width = user32.GetSystemMetrics(0)
    screen_height = user32.GetSystemMetrics(1)

    # Calculate the aspect ratio of the decoded image
    aspect_ratio = decoded_img.shape[1] / decoded_img.shape[0]

    # Calculate the maximum width and height based on screen size
    max_width = int(screen_width * 0.95)
    max_height = int(screen_height * 0.95)

    # Calculate the desired width and height while maintaining aspect ratio
    desired_width = min(max_width, int(max_height * aspect_ratio))
    desired_height = min(max_height, int(max_width / aspect_ratio))

    # Resize the image to the desired width and height
    resized_image = cv2.resize(decoded_img, (desired_width, desired_height))

    # Display the resized image
    cv2.imshow('Image', resized_image)
    cv2.waitKey(0)
    cv2.destroyAllWindows()


def showtext(decrypted_data):
    # Decode the decrypted_data from bytes to UTF-8 encoded string
    text = decrypted_data.decode('utf-8')

    # Print the decoded text
    print(text)


def menu():
    if not os.path.exists("files"):
        os.mkdir("files")
    sel = 999
    global success, unaffected, dire
    print("[1].files encryption")
    print("[2].files decryption")
    print("[3].lock/unlock folder")
    print("[4].run encrypted files")
    while sel != 0:
        try:
            sel = int(input('enter number : '))
            if sel == 1:
                success = unaffected = dire = 0
                key = input('enter password : ')
                key2 = input('verify password : ')
                if key == key2:
                    encrypt_files('./files/', key.encode())
                    print(
                        f"encryption completed - files encrypted:{success}, unaffected files:{unaffected}, folders:{dire}")
                else:
                    print('passwords not matches')
            elif sel == 2:
                success = unaffected = dire = 0
                key = input('enter password : ')
                decrypt_files('./files/', key.encode())
                print(
                    f"decryption completed - files decrypted:{success}, unaffected files:{unaffected}, folders:{dire}")
            elif sel == 3:
                if os.path.exists("Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}"):
                    unlock_folder()
                elif os.path.exists("locker"):
                    lock_folder()
                else:
                    create_folder()
            elif sel == 4:
                key = input('enter password : ')
                setfileslist('./files', key.encode())
            else:
                print("invalid number.")
        except ValueError:
            print("invalid input, numbers only.")


menu()
