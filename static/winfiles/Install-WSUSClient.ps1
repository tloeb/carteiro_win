
$WSUS_IP = "http://192.168.0.2:8530"

$PATH = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate"
$AU_PATH = $PATH + "\AU"

"Creating Registry Entries for WSUS Usage"
New-Item -Path $PATH
New-Item -Path $AU_PATH

New-ItemProperty -Path $PATH -Name WUServer -PropertyType String -Value $WSUS_IP
New-ItemProperty -Path $PATH -Name WUStatusServer -PropertyType String -Value $WSUS_IP
New-ItemProperty -Path $PATH -Name AcceptTrustedPublisherCerts -PropertyType DWORD -Value 1

New-ItemProperty -Path $AU_PATH -Name WUStatusServer -PropertyType DWORD -Value 1
"4 Items in Registry written"
$PATH

"You need to Install the WSUS Certificate manually"
"Be sure that the Certificate is imported in following stores:"
"- Local Computer/Trusted Root Certification Authorities"
"- Local Computer/Trusted Publishers"
