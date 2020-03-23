################################################################################################
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
################################################################################################

# Original Source: https://stackoverflow.com/questions/40046916/how-to-grant-permission-to-user-on-certificate-private-key-using-powershell

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