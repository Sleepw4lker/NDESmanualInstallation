Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -match "1.3.6.1.4.1.311.20.2.1" } | ForEach-Object {

    $CertificateObject = $_

    $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertificateObject)
    $KeyFileName = $PrivateKeyObject.key.UniqueName
    $KeyFilePath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$KeyFileName"
    $KeyAcl = Get-Acl -Path $KeyFilePath

    $AclEntry = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "IIS AppPool\SCEP",
        'Read',
        'None',
        'None',
        'Allow'
    )
    $KeyAcl.AddAccessRule($AclEntry)
    Set-Acl -Path $KeyFilePath -AclObject $KeyAcl

    # Returning the processed Certificate just to see that something has happened
    $CertificateObject
    
}