import os
import base64
import random
import string
import subprocess
import tempfile

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from hashlib import sha256

# put all files you want to encryption or decryption in a folder name 'files' in the same path as the project

success, unaffected, dire = 0, 0, 0


def encrypt_files(path, password):
    global success, unaffected, dire
    files_list = os.listdir(path)
    for file_name in files_list:
        if file_name[0] != '.' and not os.path.isdir(path + file_name):
            if len(file_name) <= 80:
                data = open(path + file_name, 'rb').read()

                salt = os.urandom(16)
                kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
                key = base64.urlsafe_b64encode(kdf.derive(password))
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data)

                file = open(path + file_name, 'wb')
                file.write(salt + encrypted_data)
                file.close()

                name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).encrypt(file_name.encode()).decode()
                os.rename(path + file_name, path + '.' + name)

                success += 1
            else:
                unaffected += 1
                print("file name is too long, please change it to a shorter name with less than 80 characters."
                      f"\n{file_name}")
        elif os.path.isdir(path + file_name):
            dire += 1
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
                data = open(path + file_name, 'rb').read()

                salt = data[:16]
                encrypted_data = data[16:]
                kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
                key = base64.urlsafe_b64encode(kdf.derive(password))
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)

                file = open(path + file_name, 'wb')
                file.write(decrypted_data)
                file.close()

                try:
                    name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).decrypt(
                        file_name[1:].encode()).decode()
                    success += 1
                except cryptography.fernet.InvalidToken:
                    name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                    print(f"file name is corrupted so the format is unknown, file name will be changed to {name}")
                    success += 1

                os.rename(path + file_name, path + name)
                print(f"{success + unaffected} files done.")
            except cryptography.fernet.InvalidToken:
                unaffected += 1
                print(f"{success + unaffected}.wrong password")

        elif os.path.isdir(path + file_name):
            dire += 1
            decrypt_files(path + file_name + '/', password)
        else:
            unaffected += 1
            print(f"{success + unaffected} files done.")


# create "Locker" folder, put the files you want to hide in it.


def lock_folder():
    os.system("ren locker \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
    os.system("C:\\Windows\\System32\\attrib +h +s \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
    print("folder locked")


def unlock_folder():
    password = input("enter password: ")
    if password == "bjffg7":
        os.system("C:\\Windows\\System32\\attrib -h -s \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\"")
        os.system("ren \"Control Panel.{21EC2020-3AEA-1069-A2DD-08002B30309D}\" locker")
        print("folder unlocked successfully")
    else:
        print("invalid password")


def create_folder():
    os.mkdir("locker")
    print("locker created successfully")


# show list of encrypted mp4 files in the folders


def setfileslist(path, password):
    print('\n\n\n\n\n')
    videolist = []
    dirlist = []
    files_list = os.listdir(path)
    for file_name in files_list:
        if file_name[0] == '.' and not os.path.isdir(os.path.join(path, file_name)):
            name = Fernet(base64.urlsafe_b64encode(sha256(password).digest())).decrypt(file_name[1:].encode()).decode()
            if '.mp4' in name:
                videolist.append([name, file_name])
        elif os.path.isdir(os.path.join(path, file_name)):
            dirlist.append(file_name)

    print(f'\n{path}\n')
    print("enter number to select video or change folder")
    print("enter -1 to return to the previous folder or 0 to return to main menu")

    index = 0

    if len(videolist) > 0:
        print("\nvideos list:")
        for video in videolist:
            index += 1
            print(f"{index}.{video[0]}")

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
                if sel <= len(videolist):
                    playvideo(path, videolist[sel - 1], password)
                else:
                    setfileslist(os.path.join(path, dirlist[sel - len(videolist) - 1]), password)
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


# play mp4 file using vlc player
# temp file will be created in 'AppData\Local\Temp', temp file will be deleted after vlc player closed

vlc_path = 'C:/Program Files/VideoLAN/VLC/vlc.exe'


def playvideo(path, video, password):
    data = open(os.path.join(path, video[1]), 'rb').read()

    salt = data[:16]
    encrypted_data = data[16:]
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmpfile:
        tmpfile.write(decrypted_data)

    vlc_process = subprocess.Popen([vlc_path, tmpfile.name])

    while vlc_process.poll() is None:
        pass

    if vlc_process.poll() == 0:
        tmpfile.close()
        os.remove(tmpfile.name)


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
                encrypt_files('./files/', key.encode())
                print(
                    f"encryption completed - files encrypted:{success}, unaffected files:{unaffected}, folders:{dire}")
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
