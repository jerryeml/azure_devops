function create_self_signed_and_binding_iis
{
    # Reference:https://gist.github.com/HockeyJustin/db55b359e11d06d8d53dc49a85d4b1f0
    Clear-Host
    $certificateDnsName = '*.centralus.cloudapp.azure.com' # a name you want to give to your certificate (can be anything you want for localhost)

    $siteName = "Default Web Site" # the website to apply the bindings/cert to (top level, not an application underneath!).
    $fqdn = ""                     #fully qualified domain name (empty for 'All unassigned', or e.g 'contoso.com')


    # ----------------------------------------------------------------------------------------
    # SSL CERTIFICATE CREATION
    # ----------------------------------------------------------------------------------------

    # create the ssl certificate that will expire in 2 years
    $newCert = New-SelfSignedCertificate -DnsName $certificateDnsName -CertStoreLocation cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
    "Certificate Details:`r`n`r`n $newCert"


    # ----------------------------------------------------------------------------------------
    # IIS BINDINGS
    # ----------------------------------------------------------------------------------------


    $webbindings = Get-WebBinding -Name $siteName
    $webbindings


    $hasSsl = $webbindings | Where-Object { $_.protocol -like "*https*" }

    Try
    {
        if($hasSsl)
        {
            Write-Output "ERROR: An SSL certificate is already assigned. Please remove it manually before adding this certificate."
            Write-Output "Alternatively, you could just use that certificate (provided it's recent/secure)."
            Get-WebBinding -Port 443 -Name "Default Web Site" | Remove-WebBinding
            
            "Applying TLS/SSL Certificate"
            New-WebBinding -Name $siteName -Port 443 -Protocol https -HostHeader $fqdn
            (Get-WebBinding -Name $siteName -Port 443 -Protocol "https" -HostHeader $fqdn).AddSslCertificate($newCert.Thumbprint, "my")

            "`r`n`r`nNew web bindings"
            $webbindings = Get-WebBinding -Name $siteName
            $webbindings
        }
        else
        {
            "Applying TLS/SSL Certificate"
            New-WebBinding -Name $siteName -Port 443 -Protocol https -HostHeader $fqdn
            (Get-WebBinding -Name $siteName -Port 443 -Protocol "https" -HostHeader $fqdn).AddSslCertificate($newCert.Thumbprint, "my")

            "`r`n`r`nNew web bindings"
            $webbindings = Get-WebBinding -Name $siteName
            $webbindings
        }
        "`r`n`r`nSSL Assignment Complete`r`n`r"
        Write-Host 'RetMessage ({"ret_message":"Success.","ret_code":"0"})'
    }
    Catch
    {
        "`r`n`r`nSSL Assignment Fail`r`n`r"
        Write-Host 'RetMessage ({"ret_message":"Fail.","ret_code":"1"})'
    }
}

create_self_signed_and_binding_iis