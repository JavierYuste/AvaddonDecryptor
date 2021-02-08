#include <iostream>
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <strsafe.h>
#include <string>



// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define KEYLENGTH  32
#define ENCRYPT_BLOCK_SIZE 8192


void ErrorExit()
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("Function failed with error %d: %s"), dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw);
}

int wmain(int argc, wchar_t** argv)
{
    
    if (argc != 4) {
        _tprintf(TEXT("Usage: DecryptFile.exe [encrypted_file] [dest] [key]\n [encrypted_file] is the file to be decrypted\n [dest] is the name of the decrypted file to be created\n [key] is a file that contains the bytes of the session key\n"));
        return 0;
    }

    HANDLE hEncryptedFile = INVALID_HANDLE_VALUE;
    HANDLE hDecryptedFile = INVALID_HANDLE_VALUE;
    HANDLE infile = INVALID_HANDLE_VALUE;

    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hDuplicateKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;

    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount = 8192;
    PBYTE pbBuffer2 = NULL;
    DWORD dwBlockLen2 = 32;
    DWORD dwCount2 = 8192;
    bool fEOF = FALSE;
    bool fReturn = true;

    int i;

    // Read key
    infile = CreateFile(
        argv[3],
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != infile)
    {
        _tprintf(
            TEXT("The key bytes file, %s, is open. \n"),
            argv[3]);
    }
    else
    {
        _tprintf(
            TEXT("The key bytes file, %s, could not be opened. \n"),
            argv[3]);
        ErrorExit();
    }

    //---------------------------------------------------------------
    // Allocate memory. 
    if (pbBuffer2 = (BYTE*)malloc(dwBlockLen2))
    {
        _tprintf(
            TEXT("Memory has been allocated for the buffer. \n"));
    }
    else
    {
        _tprintf(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
    }

    if (!ReadFile(
        infile,
        pbBuffer2,
        dwBlockLen2,
        &dwCount2,
        NULL))
    {
        _tprintf(
            TEXT("Error reading plaintext!\n"));
        ErrorExit();
    }

    // Get key
    BYTE startState[32] = { 0xd0,0x48,0x34,0x6b,0xc7,0x0a,0x78,0xa3,0xee,0x6d,0xb3,0x08,0x37,0x4a,0xcb,0xd5,0xdf,0xb1,0x6a,0x17,0x9d,0x1e,0xae,0x3a,0xc2,0xa7,0xa0,0xa2,0x89,0x73,0xa4,0x80 };
    CopyMemory(startState, pbBuffer2, 32);
    const DWORD AES_KEY_LENGTH = 32;
    struct {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[AES_KEY_LENGTH];
    } keyBlob;

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENH_RSA_AES_PROV,
        PROV_RSA_AES,
        0))
    {
        _tprintf(
            TEXT("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        _tprintf(
            TEXT("Error during CryptAcquireContext!\n"),
            GetLastError());
        ErrorExit();
        goto Exit_MyEncryptFile;
    }

    //-----------------------------------------------------------
    // http://rette.iruis.net/2017/05/aes-256-%EC%95%94%ED%98%B8%ED%99%94%EB%A5%BC-%EC%9C%84%ED%95%9C-wincrypt-%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0/

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.cbKeySize = AES_KEY_LENGTH;
    CopyMemory(keyBlob.rgbKeyData, startState, AES_KEY_LENGTH);

    if (CryptImportKey(hCryptProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        _tprintf(TEXT("Key has been imported.\n"));
    }
    else {
        _tprintf(TEXT("Error importing the key.\n"));
        ErrorExit();
        goto Exit_MyEncryptFile;
    }


    //---------------------------------------------------------------
    // Open the encrypted file. 
    hEncryptedFile = CreateFile(
        argv[1],
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hEncryptedFile)
    {
        _tprintf(
            TEXT("The encrypted file, %s, is open. \n"),
            argv[1]);
    }
    else
    {
        _tprintf(
            TEXT("The encrypted file, %s, could not be opened. \n"),
            argv[1]);
        ErrorExit();
        goto Exit_MyEncryptFile;
    }

    // Open the destination file. 
    hDecryptedFile = CreateFile(
        argv[2],
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hEncryptedFile)
    {
        _tprintf(
            TEXT("The decrypted file, %s, is open. \n"),
            argv[2]);
    }
    else
    {
        _tprintf(
            TEXT("The decrypted file, %s, could not be opened. \n"),
            argv[2]);
        ErrorExit();
        goto Exit_MyEncryptFile;
    }
    
    dwBlockLen = ENCRYPT_BLOCK_SIZE;

    CryptEncrypt(
        hKey,
        0,
        0,
        0,
        NULL,
        &dwCount,
        0);
    dwBufferLen = dwCount;

    //---------------------------------------------------------------
    // Allocate memory. 
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        _tprintf(
            TEXT("Memory has been allocated for the buffer. \n"));
    }
    else
    {
        _tprintf(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
        goto Exit_MyEncryptFile;
    }
    

    if (CryptDuplicateKey(
        hKey,
        NULL,
        0,
        &hDuplicateKey))
    {
        printf("The session key has been duplicated. \n");
    }
    else
    {
        _tprintf(
            TEXT("The session key could not be duplicated.\n"));
        ErrorExit();
        goto Exit_MyEncryptFile;
    }

    if (hEncryptedFile)
    {
        CloseHandle(hEncryptedFile);
    }

    //---------------------------------------------------------------
    // Open the encrypted file again to be decrypted
    hEncryptedFile = CreateFile(
        argv[1],
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hEncryptedFile)
    {
        _tprintf(
            TEXT("The encrypted file, %s, is open. \n"),
            argv[1]);
    }
    else
    {
        _tprintf(
            TEXT("The encrypted file, %s, could not be opened. \n"),
            argv[1]);
        ErrorExit();
        goto Exit_MyEncryptFile;
    }

    // Decrypt

    if (CryptDuplicateKey(
        hKey,
        NULL,
        0,
        &hDuplicateKey))
    {
        printf("The session key has been duplicated. \n");
    }
    else
    {
        _tprintf(
            TEXT("The session key could not be duplicated\n"));
        ErrorExit();
        goto Exit_MyEncryptFile;
    }

    i = 0;
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(
            hEncryptedFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL))
        {
            _tprintf(
                TEXT("Error reading plaintext!\n"));
            ErrorExit();
            goto Exit_MyEncryptFile;
        }
        i = i + dwCount;
        if (dwCount < dwBlockLen or i >= 0x100000) // Avaddon only encrypts the first 0x100000, handle the rest in Python
        {
            fEOF = TRUE;
        }

        //dwCount = 8192;
        _tprintf(
            TEXT("%d: Decrypting %d bytes. \n"),
            i, dwCount);
        //-----------------------------------------------------------
        // Decrypt data. 
        if (!CryptDecrypt(
            hDuplicateKey,
            NULL,
            FALSE,
            0,
            pbBuffer,
            &dwCount))
        {
            _tprintf(
                TEXT("Error during CryptDecrypt. \n"));
            ErrorExit();
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Write the decrypted data to the destination file. 
        if (!WriteFile(
            hDecryptedFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL))
        {
            _tprintf(
                TEXT("Error writing ciphertext.\n"));
            goto Exit_MyEncryptFile;
        }
    } while (!fEOF);
    _tprintf(TEXT("Finished decrypting\n"));


Exit_MyEncryptFile:
    //---------------------------------------------------------------
    // Close files.
    if (hEncryptedFile)
    {
        CloseHandle(hEncryptedFile);
    }

    if (hDecryptedFile)
    {
        CloseHandle(hDecryptedFile);
    }

    //---------------------------------------------------------------
    // Free memory. 
    if (pbBuffer)
    {
        free(pbBuffer);
    }


    //-----------------------------------------------------------
    // Release the hash object. 
    if (hHash)
    {
        if (!(CryptDestroyHash(hHash)))
        {
            _tprintf(
                TEXT("Error during CryptDestroyHash.\n"));
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            _tprintf(
                TEXT("Error during CryptDestroyKey!\n"));
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            _tprintf(
                TEXT("Error during CryptReleaseContext!\n"));
        }
    }

    return fReturn;
}