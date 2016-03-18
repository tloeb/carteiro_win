Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
New-Item -Path C:\ -Name WSUS -ItemType Directory
cd $env:ProgramFiles
.\Update Services\Tools\WsusUtil.exe postinstall CONTENT_DIR=C:\WSUS
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'