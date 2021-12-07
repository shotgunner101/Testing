<#
.SYNOPSIS
Search a downloaded Swiss aircraft registry database for a Swiss aircraft registation and if found, return the aircraft manufacturer and model (tab-delimited)

.DESCRIPTION
First, create a subdirectory 'HB' in this script's parent folder.
Next, download the Swiss aircraft registry database in CSV format (see links section), and move the file 'Swiss Aircraft Register.csv' to the 'HB' folder.
Now run this script with an Australian aircraft registration as its only parameter (see examples section).
The script will first look for the specified registration code in column 2 of the 'Swiss Aircraft Register.csv' file.
If a match is found, the manufacturer and model are found in columns 6 and 7.
The script will display a tab-delimited string with the registration, the manufacturer and the aircraft model (<registration><tab><manufacturer><tab><model>).
If the script was started by another PowerShell script, the calling PowerShell script may also read the manufacturer and model from the variables $Manufacturer and $Model, passed on by this script.
If the script was started by a batch file, the calling batch file can use 'FOR /F' on this PowerShell script's screen output to find the manufacturer and model.
Get-Help './AirRegHBCmd.ps1' -Examples will show 2 examples of this script being called by another script.

.PARAMETER Registration
A valid Swiss aircraft registration, e.g. HB-1044

.PARAMETER Quiet
Ignore all errors and do not display any error messages; in case of errors, just terminate with return code 1.

.PARAMETER Version
Show this script's version number; if combined with -Verbose show full script path, version number and last/modified/release date

.PARAMETER CheckDB
If the required local database can be found, returns True and exit code 0; if not, returns False and exit code 1.

.PARAMETER Help
Show the script's help screen

.PARAMETER Debug
Show some progress messages

.OUTPUTS
If a match is found: a tab-delimited string with <registration><tab><manufacturer_and_model>, and if -NoBreak switch is used: variables $Manufacturer set to aircraft manufacturer $Model set to aircraft model
If no match is found: False

.EXAMPLE
. ./AirRegHBCmd.ps1 HB-1044
Will return tab-delimited string "HB-1044<tab>SEGELFLUGZEUGBAU A. NEUKOM<tab>AN 66 C", and set variables $Manufacturer to "HB-1044	SEGELFLUGZEUGBAU A. NEUKOM" and $Model to "AN 66 C"

.EXAMPLE
"HB-1044" | . ./AirRegHBCmd.ps1
Will also return tab-delimited string HB-1044<tab>SEGELFLUGZEUGBAU A. NEUKOM<tab>AN 66 C", and set variables $Manufacturer to "HB-1044	SEGELFLUGZEUGBAU A. NEUKOM" and $Model to "AN 66 C"

.EXAMPLE
. ./AirRegHBCmd.ps1 "HB-1044" -Debug
This will return:

Start searching "HB-1044" in "Swiss Aircraft Register.csv" file at <date> <time>
Found a match at 2021-08-17 15:13:59
HB-1044	SEGELFLUGZEUGBAU A. NEUKOM	AN 66 C

Finished at <date> <time> (elapsed time <time elapsed>)

.EXAMPLE
Create and run the following PowerShell script:
===============================================================
$Registration = 'HB-1044' ; $Manufacturer = '' ; $Model = ''
[void] ( . "$PSScriptRoot\AirRegHBCmd.ps1" -Registration $Registration )
Write-Host ( "Registration : {0}`nManufacturer : {1}`nModel        : {2}" -f $Registration, $Manufacturer, $Model )
===============================================================

Besides setting variables $Manufacturer to "THB-1044	SEGELFLUGZEUGBAU A. NEUKOM" and $Model to "AN 66 C", it will return:

Registration : HB-1044
Manufacturer : HB-1044	SEGELFLUGZEUGBAU A. NEUKOM
Model        : AN 66 C

.EXAMPLE
Create and run the following batch file:
===============================================================
REM Note that there should only be a TAB and nothing else between delims= and the doublequote
FOR /F "tokens=1-3 delims=	" %%A IN ('powershell . ./AirRegHBCmd.ps1 HB-1044') DO (
	ECHO Registration : %%A
	ECHO Manufacturer : %%B
	ECHO Model        : %%C
)
===============================================================

It will return:

Registration : HB-1044
Manufacturer : HB-1044	SEGELFLUGZEUGBAU A. NEUKOM
Model        : AN 66 C

.LINK
Script written by Rob van der Woude:
https://www.robvanderwoude.com/

.LINK
Swiss Aircraft Register:
https://app02.bazl.admin.ch/web/bazl/en/#/lfr/search

.LINK
Capture -Debug parameter by mklement0 on StackOverflow.com:
https://stackoverflow.com/a/48643616
#>

param (
	[parameter( ValueFromPipeline )]
	[ValidatePattern("(^\s*$|[\?/]|^-|^HB-([A-Z]{3}|\d{2,4})$)")]
	[string]$Registration,
	[switch]$CheckDB,
	[switch]$Version,
	[switch]$Quiet,
	[switch]$Help
)

$progver = "1.00"

$Registration = $Registration.ToUpper( )
$Manufacturer = ''
$Model = ''
[bool]$Debug = ( $PSBoundParameters.ContainsKey( 'Debug' ) )
[bool]$Verbose = ( $PSBoundParameters.ContainsKey( 'Verbose' ) )

if ( $Version ) {
	if ( $Verbose ) {
		$lastmod = ( [System.IO.File]::GetLastWriteTime( $PSCommandPath ) )
		if ( $lastmod.ToString( "h.mm" ) -eq $progver ) {
			"`"{0}`", Version {1}, release date {2}" -f $PSCommandPath, $progver, $lastmod.ToString( "yyyy-MM-dd" )
		} else {
			# if last modified time is not equal to program version, the script has been tampered with
			"`"{0}`", Version {1}, last modified date {2}" -f $PSCommandPath, $progver, $lastmod.ToString( "yyyy-MM-dd" )
		}
	} else {
		$progver
	}
	exit 0
}

$dbfolder = ( Join-Path -Path $PSScriptRoot -ChildPath 'HB' )
$dbfile = ( Join-Path -Path $dbfolder -ChildPath 'Swiss Aircraft Register.csv' )

if ( $CheckDB ) {
	if ( Test-Path -Path $dbfile -PathType 'Leaf' ) {
		[bool]$true
		exit 0
	} else {
		[bool]$false
		exit 1
	}
}

if ( $Help -or [string]::IsNullOrWhiteSpace( $Registration ) -or ( $Registration -match "[/\?]" ) ) {
	Clear-Host
	Write-Host ( "`"{0}`", Version {1}" -f $PSCommandPath, $progver ) -NoNewline
	$lastmod = ( [System.IO.File]::GetLastWriteTime( $PSCommandPath ) )
	if ( $lastmod.ToString( "h.mm" ) -eq $progver ) {
		Write-Host ", release date " -NoNewline
	} else {
		# if last modified time is not equal to program version, the script has been tampered with
		Write-Host ", last modified date " -NoNewline
	}
	Write-Host $lastmod.ToString( "yyyy-MM-dd" )
	Write-Host
	Get-Help $PSCommandPath -Full
	exit -1
}

if ( Test-Path -Path $dbfile -PathType 'Leaf' ) {
	if ( $Debug ) {
		$StopWatch = [system.diagnostics.stopwatch]::StartNew( )
		Write-Host ( "Start searching `"{0}`" in `"Swiss Aircraft Register.csv`" file at {1}" -f $Registration, ( Get-Date ) )
	}
    $delimiter = ';'
    $pattern = "^`"\d+`"{0}`"{1}`"{0}`"[^\n\r]+" -f $delimiter, $Registration
	$record = ( ( Get-Content -Path $dbfile ) -match $pattern )
	if ( $record ) {
        if ( $record.Split( $delimiter ).Count -gt 6 ) {
			$Manufacturer = $record.Split( $delimiter )[5] -replace '"',''
			$Model = $record.Split( $delimiter )[6] -replace '"',''
			if ( $Debug ) {
				Write-Host ( "Found a match at {0}" -f ( Get-Date ) )
			}
		}
	}
	"{0}`t{1}`t{2}" -f $Registration, $Manufacturer, $Model | Out-String
	if ( $Debug ) {
		Write-Host ( "Finished at {0} (elapsed time {1})`n`n" -f ( Get-Date ), $StopWatch.Elapsed )
		$StopWatch.Stop( )
	}
} else {
	if ( $Quiet ) {
		if ( $Debug ) {
			Write-Host ( "Downloaded Swiss aircraft registry database file `"{0}`" not found" -f $dbfile )
		}
		exit 1
	} else {
		$message = "No downloaded Swiss aircraft registry database was found.`n`nDo you want to open the download webpage for the database now?"
		$title   = 'No Database Found'
		$buttons = 'YesNo'
		Add-Type -AssemblyName System.Windows.Forms
		$answer = [System.Windows.Forms.MessageBox]::Show( $message, $title, $buttons )
		if ( $answer -eq "Yes" ) {
			$url = 'https://app02.bazl.admin.ch/web/bazl/en/#/lfr/search'
			Start-Process $url
		} else {
			ShowHelp( 'No downloaded Swiss aircraft registry database found, please download it and try again' )
		}
	}
}
