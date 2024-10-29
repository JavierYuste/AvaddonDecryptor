import argparse
import filecmp
import mmap
import subprocess
import json
import struct
import os
import shutil
import logging
import time

logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d %I:%M:%S', level=logging.INFO)
import sys

path = os.path.abspath('minidump')
if path not in sys.path:
    sys.path.append(path)
from minidump.minidumpfile import *

script_dir = os.path.dirname(os.path.abspath(__file__))

# Dump the process with procdump.exe -ma <PID>
# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size):
# 106600000100000020000000

description = """
	Decrypts Avaddon encrypted files in a specific folder. 
	The decryption is done recursively, which means that it may decrypt the whole system if the root path is C:\\.
	To do this, three files are needed: 
	    1) a dump of the Avaddon process;
	    2) an encrypted file;
	    3) the original version of the encrypted file.
	The encrypted file is decrypted with all the valid session keys found in the Avaddon memory dump. 
	If decrypting the encrypted file with one of such keys results in a file that is identical to the original one, 
	it means that we have recovered the session key. 
	If that is the case, we proceed to decrypt all the encrypted files in the specified folder.
	IMPORTANT: BACKUP YOUR SYSTEM BEFORE LAUNCHING THE DECRYPTOR. 
	THIS TOOL IS PROVIDED AS A PROOF OF CONCEPT, WITHOUT ANY WARRANTY.
	"""

p = argparse.ArgumentParser(description=description)
p.add_argument('-f', '--file', type=str, metavar='FILE', dest='file', help='Encrypted file')
p.add_argument('-o', '--original', type=str, metavar='FILE', dest='original', help='Original version of the encrypted file file')
p.add_argument('-d', '--dump', type=str, metavar='FILE', dest='dump', help='Memory dump of the Avaddon process')
p.add_argument('--folder', type=str, dest='folder', help='Folder to decrypt recursively', default="C:/")


def get_signature_data(file):
    with open(file, "r+b") as f:
        # Memory-map the file, size 0 means whole file
        mm = mmap.mmap(f.fileno(), 0)
        signature = mm[-24:]
        mm.close()
    # Original file size written in the signature
    original_file_size = int.from_bytes(signature[0:8], byteorder='little')
    harcoded_signature = struct.unpack('<L', signature[16:20])[0]
    # Those are bytes, we need to convert them to integer
    print(f"Signature: {signature}")
    print(f"Original file size unpacked: {original_file_size} ({hex(original_file_size)})")
    print(f"Hardcoded signature: {hex(harcoded_signature)}")

    data = dict()
    data['original_size'] = original_file_size
    return data


def remove_signature(file):
    # Remove signature in the copy
    file_size = os.stat(file).st_size
    print(f"Size of the encrypted file with signature: {file_size}")
    with open(file, "r+b") as f:
        # Remove the signature
        f.truncate(
            file_size - 24 - 512)  # The ransom appends 512 bytes after encrypting, which correspond to the victim ID
    print(f"Size of the encrypted file without signature: {os.stat(file).st_size}")
    return file


def get_keys_from_offsets(dump, offsets):
    possible_keys = list()
    pointers_to_possible_keys = list()
    with open(dump, "r+b") as f:
        # Memory-map the file, size 0 means whole file
        mm = mmap.mmap(f.fileno(), 0)
        for offset in offsets:
            # Offset points to a structure key_data_s
            # struct key_data_s -> void* key_bytes;
            # A pointer to the key is at offset 16 of the structure, but we skipped the first four bytes bc they may be unknown
            mm.seek(offset + 12)
            # Read pointer
            key_data_pointer = mm.read(4)
            ba = bytearray.fromhex(key_data_pointer.hex())
            ba.reverse()
            s = ''.join(format(x, '02x') for x in ba)
            pointers_to_possible_keys.append(s.upper())
            mm.seek(offset)
            print(f"Structure found: {mm.read(16).hex()}")
        # Close the map
        mm.close()
    # Get possible keys
    minidump_reader = open_minidump(dump)
    for pointer in pointers_to_possible_keys:
        possible_keys.append(read_vaddr(reader=minidump_reader, position=int(pointer, 16), count=32))

    return possible_keys, pointers_to_possible_keys


def search_pattern(dump, pattern):
    # Fixed TODO, paths relative to main file
    subprocess.run([f"python.exe",  # remember to activate venv
                    f"{script_dir}/searchbin.py", "-p", str(pattern),
                    os.path.abspath(dump)], stdout=subprocess.PIPE)
    with open(f"{script_dir}/testing.matches", "r") as f:
        offsets = json.load(f)
    return offsets['matches']


def decrypt_file(file, key):
    print(f"\tDecrypting file {file} with key {key}")
    with open("key_bytes", 'wb') as f:
        f.write(key)
    key_path = os.path.abspath("key_bytes")
    # Invoke C++ program, which decrypts a specified file with a given key
    abs_path = os.path.abspath(file)
    filename, file_extension = os.path.splitext(abs_path)
    print(f"\tDecrypting {abs_path}")
    subprocess.run(["DecryptFile.exe", abs_path, filename, key_path], stdout=subprocess.PIPE)
    if os.stat(abs_path).st_size > 0x100000:
        with open(abs_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0)
            with open(filename, "r+b") as f2:
                # Memory-map the file, size 0 means whole file
                mm.seek(0x100000)
                f2.seek(0, 2)
                while mm.tell() < mm.size() and (mm.size() - mm.tell()) > 0x2000:
                    f2.write(mm.read(0x2000))
                if mm.tell() < mm.size():
                    f2.write(mm.read(mm.size() - mm.tell()))
            mm.close()
    return filename


def open_minidump(filename):
    mini = MinidumpFile.parse(filename)
    reader = mini.get_reader().get_buffered_reader()
    return reader


def read_vaddr(reader, position, count):
    reader.move(position)
    data = reader.read(count)
    return data


def decrypt_whole_system(rootdir, key, extension):
    print("Decrypting whole system")
    total_files = 0
    total_encrypted_files = 0
    start_time = time.perf_counter()
    for subdir, dirs, files in os.walk(os.path.abspath(rootdir)):
        for file in files:
            total_files += 1
            file_path = os.path.abspath(os.path.join(subdir, file))
            if (file_path.endswith(extension)) and "$Recycle.Bin" not in file_path:
                try:
                    print(f"> Found file {file_path}")
                    total_encrypted_files += 1
                    data = get_signature_data(file_path)
                    print(f"\tRemoving signature")
                    data['encrypted_truncated_file'] = remove_signature(file_path)
                    print("\tDecrypting file")
                    decrypted_file = decrypt_file(data['encrypted_truncated_file'], key)
                    print(f"\tTruncating to {data['original_size']}")
                    with open(decrypted_file, "r+b") as f:
                        f.truncate(data["original_size"])
                    os.remove(file_path)
                except OSError:
                    print("Permissions denied?")
                    pass

    print(f"\n--- SUMMARY ---"
          f"\nTotal files: {total_files}"
          f"\nDecrypted files: {total_encrypted_files}"
          f"\nTime: {time.perf_counter() - start_time}")


def main():
    args = p.parse_args()
    original_file = os.path.abspath(args.original)
    encrypted_file = os.path.abspath(args.file)
    filename, file_extension = os.path.splitext(encrypted_file)
    dump = os.path.abspath(args.dump)
    pattern = "106600000100000020000000"

    # Get a list of offsets of the matches with searchbin
    offsets = search_pattern(dump=dump, pattern=pattern)
    print(f"Offsets: {offsets}")
    # Get each possible key from the list of offsets
    possible_keys, pointers_to_possible_keys = get_keys_from_offsets(dump=dump, offsets=offsets)
    print(f"Pointers to possible keys: {pointers_to_possible_keys}")
    print(f"Possible keys: {possible_keys}")
    # Get original file size and perform initial truncate
    shutil.copy(encrypted_file, f"{encrypted_file}.backup_copy")
    data = get_signature_data(encrypted_file)
    data['encrypted_truncated_file'] = remove_signature(encrypted_file)
    # Try each key till success
    success = False
    i = 0
    possible_keys = list(dict.fromkeys(possible_keys))
    while not success and i < len(possible_keys):
        # Decrypt file
        decrypted_file = decrypt_file(data['encrypted_truncated_file'], possible_keys[i])
        # Truncate to original size
        with open(decrypted_file, "r+b") as f:
            f.truncate(data["original_size"])
        # Compare with the original file
        success = filecmp.cmp(decrypted_file, original_file, shallow=True)
        if not success:
            i = i + 1

    if success:
        print(f"[SUCCESS] Found the correct symmetric key: {possible_keys[i]}")
        os.remove(data['encrypted_truncated_file'])
        decrypt_whole_system(args.folder, possible_keys[i], file_extension)
    else:
        shutil.copy(f"{encrypted_file}.backup_copy", encrypted_file)
        os.remove(f"{encrypted_file}.backup_copy")
        print("[FAIL] Did not find the correct symmetric key")


if __name__ == '__main__':
    main()
