# Source for base code of enable priviledges and take-ownership: 
# https://stackoverflow.com/questions/24366162/set-acl-requested-registry-access-is-not-allowed

### Function definitions
function Enable-Privilege($Privilege) {
  $Definition = @'
using System;
using System.Runtime.InteropServices;
public class AdjPriv {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
    ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
    ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid {
    public int Count;
    public long Luid;
    public int Attr;
  }
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege) {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = new IntPtr(processHandle);
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
      ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero,
      IntPtr.Zero);
    return retVal;
  }
}
'@
  $ProcessHandle = (Get-Process -id $pid).Handle
  $type = Add-Type $definition -PassThru
  $type[0]::EnablePrivilege($processHandle, $Privilege)
}

function take-ownership($rootkey, $key) {
    # Debug
    Write-Host "Taking ownership of:" $rootKey":\"$key
    # Convert rootkey to correct naming
    switch -regex ($rootKey) {
        'HKCU|HKEY_CURRENT_USER'    { $rootKey_alt = 'CurrentUser' }
        'HKLM|HKEY_LOCAL_MACHINE'   { $rootKey_alt = 'LocalMachine' }
        'HKCR|HKEY_CLASSES_ROOT'    { $rootKey_alt = 'ClassesRoot' }
        'HKCC|HKEY_CURRENT_CONFIG'  { $rootKey_alt = 'CurrentConfig' }
        'HKU|HKEY_USERS'            { $rootKey_alt = 'Users' }
    }

    # Take ownership
    $regKey = [Microsoft.Win32.Registry]::$rootKey_alt.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
    $idRef = [System.Security.Principal.NTAccount]"Administrators"
    $acl = New-Object System.Security.AccessControl.RegistrySecurity
    $acl.SetOwner($idRef)
    $regKey.SetAccessControl($acl)

    # Give Full Control to owner
    $regKey = $regKey.OpenSubKey('', 'ReadWriteSubTree', 'ChangePermissions')
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($idRef, 'FullControl','None','None','Allow')
    $acl.SetAccessRule($rule)
    $regKey.SetAccessControl($acl)

    # Remove duplicate (For some reason an entry with inheritance None remains as left over otherwise)
    $acl = Get-Acl REGISTRY::$rootKey\$key
    foreach ($entry in $acl.Access) {
        if (!$entry.IsInherited) {
            $acl.RemoveAccessRule($entry)
        }
    }
    $regKey.SetAccessControl($acl)
}

### Main
# Ensure proper priviledges for registry access
do {} until (Enable-Privilege SeTakeOwnershipPrivilege)
# HKEY_CLASSES_ROOT\Directory\Background\shell keys
take-ownership "HKCR" "Directory\Background\shell\cmd"
take-ownership "HKCR" "Directory\Background\shell\cmd\command"
take-ownership "HKCR" "Directory\Background\shell\Powershell"
take-ownership "HKCR" "Directory\Background\shell\Powershell\command"
# HKEY_CLASSES_ROOT\Directory\shell keys
take-ownership "HKCR" "Directory\shell\cmd"
take-ownership "HKCR" "Directory\shell\cmd\command"
take-ownership "HKCR" "Directory\shell\Powershell"
take-ownership "HKCR" "Directory\shell\Powershell\command"
# HKEY_CLASSES_ROOT\Drive\shell keys
take-ownership "HKCR" "Drive\shell\cmd"
take-ownership "HKCR" "Drive\shell\cmd\command"
take-ownership "HKCR" "Drive\shell\Powershell"
take-ownership "HKCR" "Drive\shell\Powershell\command"


# Installation
Write-Host "Press the following keys to choose context-menu installation:"
Write-Host "1 - PowerShell only" 
Write-Host "2 - PowerShell and CMD"
$install = Read-Host
switch -regex ($install) {
    '1'    { regedit.exe $PSScriptRoot\"SetKeys-PowerShell.reg" }
    '2'    { regedit.exe $PSScriptRoot\"SetKeys.reg" }
    default { Read-Host -Prompt "Invalid input. Installation terminated" }
}