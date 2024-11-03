# FileEncryptDecrypt.ps1
# Created by n16h7h4wk00

param (
    [string]$Mode,             # "Encrypt" or "Decrypt"
    [string]$FilePath,         # Path to the file to encrypt/decrypt
    [string]$Password,         # Password to generate encryption key
    [string]$OutputPath        # Path to save the encrypted/decrypted file
)

function Generate-AESKey {
    param (
        [string]$Password
    )
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $key = $sha256.ComputeHash($passwordBytes)
    $sha256.Dispose()
    return $key
}

function Encrypt-File {
    param (
        [string]$FilePath,
        [string]$Password,
        [string]$OutputPath
    )
    $key = Generate-AESKey -Password $Password
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.GenerateIV()

    $iv = $aes.IV
    [byte[]]$fileContent = [System.IO.File]::ReadAllBytes($FilePath)
    $encryptor = $aes.CreateEncryptor()

    $encryptedContent = $encryptor.TransformFinalBlock($fileContent, 0, $fileContent.Length)
    $encryptor.Dispose()
    $aes.Dispose()

    # Write IV and encrypted content to output file
    [System.IO.File]::WriteAllBytes($OutputPath, $iv + $encryptedContent)
    Write-Output "File encrypted and saved to $OutputPath"
}

function Decrypt-File {
    param (
        [string]$FilePath,
        [string]$Password,
        [string]$OutputPath
    )
    $key = Generate-AESKey -Password $Password
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key

    # Read the IV and encrypted content from the file
    [byte[]]$fileContent = [System.IO.File]::ReadAllBytes($FilePath)
    $aes.IV = $fileContent[0..15] # First 16 bytes are the IV
    $encryptedContent = $fileContent[16..($fileContent.Length - 1)]

    $decryptor = $aes.CreateDecryptor()
    $decryptedContent = $decryptor.TransformFinalBlock($encryptedContent, 0, $encryptedContent.Length)
    $decryptor.Dispose()
    $aes.Dispose()

    # Write decrypted content to output file
    [System.IO.File]::WriteAllBytes($OutputPath, $decryptedContent)
    Write-Output "File decrypted and saved to $OutputPath"
}

if ($Mode -eq "Encrypt") {
    Encrypt-File -FilePath $FilePath -Password $Password -OutputPath $OutputPath
} elseif ($Mode -eq "Decrypt") {
    Decrypt-File -FilePath $FilePath -Password $Password -OutputPath $OutputPath
} else {
    Write-Output "Invalid mode. Use 'Encrypt' or 'Decrypt'."
}
