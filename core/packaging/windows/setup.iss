; AegisAI Windows Installer Script
; Using Inno Setup

[Setup]
AppName=AegisAI Antivirus
AppVersion=1.0.0
AppPublisher=AegisAI Security
AppPublisherURL=https://aegisai.com
AppSupportURL=https://aegisai.com/support
AppUpdatesURL=https://aegisai.com/updates

DefaultDirName={autopf}\AegisAI
DefaultGroupName=AegisAI
AllowNoIcons=yes
LicenseFile=..\..\LICENSE
OutputDir=.
OutputBaseFilename=aegisai-setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 0,6.1

[Files]
Source: "..\..\dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\AegisAI"; Filename: "{app}\aegisai.exe"
Name: "{autodesktop}\AegisAI"; Filename: "{app}\aegisai.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\aegisai.exe"; Description: "{cm:LaunchProgram,AegisAI}"; Flags: nowait postinstall skipifsilent

[InstallDelete]
Type: filesandordirs; Name: "{app}\*"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"