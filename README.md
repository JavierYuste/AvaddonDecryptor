# AvaddonDecryptor

This is an open-sourced tool to decrypt systems infected with Avaddon ransomware. 
In order to do so, the computer should not have been powered off after the infection.

## Instructions

1) Download the Sysinternals Suite to the infected system. 
   Executable files are not encrypted by Avaddon.
   In particular, you will need two tools from the Suite: Process Explorer and ProcDump.
   
2) Open Process Explorer as administrator and locate the Avaddon process.
**Suspend** (do not kill it!) the process and note the PID of the process.
   
3) Open a cmd as administrator and dump the memory of the process.
To do so, you can run 'procdump.exe -ma \<PID\>', where \<PID\> is the PID of the ransomware process we saw in the second step.
   
4) In addition to the memory dump, you will need an encrypted file and the original version of such encrypted file. 
   If you do not have any, you may drop a copy of a dummy text file to the infected system prior to suspending the process (or drop the file, resume the process, wait until the file is encrypted and suspend the process again).
   I usually leave the memory dump, the encrypted file and its original version in the 'dump_and_original_file' folder.
   
5) Open a cmd as administrator (important, since the process will need administrator rights to decrypt some folders) and run the decryptor as follows:

    `python3 main.py -f <encrypted_file> -o <original_file> -d <memory_dump> --folder <folder_to_decrypt>`

Note that decryption of the given folder is done recursively. So, to decrypt the whole system, the <folder_to_decrypt> value should be 'C:\\'

# Strings decryption

./utils/decrypt_strings.py contains a Python script to decrypt and label obfuscated strings of Avaddon in Binary Ninja. 
Note that it was developed for the first versions of Avaddon. Later versions use different XOR keys, although the overall process remains similar.

# Credits

searchbin.py is a slightly modified version of https://github.com/Sepero/SearchBin. I have only added a json class to output the results.

# Citing

Details of this work can be found in the [full article](https://www.sciencedirect.com/science/article/pii/S0167404821002121). Please cite as:

```
@article{Yuste2021Avaddon,
   title = {Avaddon ransomware: An in-depth analysis and decryption of infected systems},
   journal = {Computers & Security},
   volume = {109},
   pages = {102388},
   year = {2021},
   issn = {0167-4048},
   doi = {https://doi.org/10.1016/j.cose.2021.102388},
   url = {https://www.sciencedirect.com/science/article/pii/S0167404821002121},
   author = {Javier Yuste and Sergio Pastrana}
}
```
