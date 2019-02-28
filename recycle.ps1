# grab_recycle.ps1

# Grabs the Recycle Bin of all users of a system and outputs the contents.
# Output will include all $I File information, as well as any files that might
# have been placed there by a malicious user/process.
$ErrorActionPreference = "silentlycontinue"
$WIN7IHEADERSTR = "0100000000000000"
$WIN7FILEPATHIDX = 24
$WIN10IHEADERSTR = "0200000000000000"

# Returns MD5 hash of file < 50MB
function Get-MdHash
{
	param($file,
		[int] $size)
	
	# If file size is greater than 50MB, skip hashing
	If ($size -gt 52428800){
		return "00000000000000000000000000000000"
	}
	Else{
		$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
		$hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($file)))
		return $hash -replace '-',''
	}
}

# Returns SHA-1 hash of file < 50MB
function Get-ShaHash
{
	param($file,
		[int] $size)
	
	# If file size is greater than 50MB, skip hashing
	If ($size -gt 52428800){
		return "00000000000000000000000000000000"
	}
	Else{
		$sha = new-object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
		$hash = [System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($file)))
		return $hash -replace '-',''
	}
}

function Get-DeletedMetadata
{
	param($file)
	# Header
	# If header matches a $I file, go through parser
	# 	Else, just print file name and type
	$header = Get-Content -Encoding Byte -path $file -totalcount 8
	$header_str = [System.BitConverter]::ToString($header) -replace '-'
	#Windows 10
	If ($header_str -match "0200000000000000"){
		$size = (Get-Content -Encoding Byte -path $file)[8 .. 15]
		$file_size = [System.BitConverter]::ToInt64($size,0)
		$temp_time = (Get-Content -Encoding Byte -path $file)[16 .. 23]
		$temp = [System.BitConverter]::ToInt64($temp_time,0)
		$del_time = [DateTime]::FromFileTime($temp)
		#Grab original file location
		$diff = (Get-Item $file).Length
		$orig_path = (Get-Content -Encoding Byte -path $file)[28 .. $diff]
		$path_str = [System.Text.Encoding]::Ascii.GetString($orig_path) -replace "\x00"
		$filename = (Get-Item $file).Name
		$mdhash = Get-MdHash -file $file -size $diff
		$shahash = Get-ShaHash -file $file -size $diff
		
		$filedata = " Filename=`""+[string]$filename+"`""+" Header=`""+[string]$header_str +"`"" +" Original_size=`""+[string]$file_size +"`"" +" Original_file_path=`""+[string]$path_str +"`"" +" Deleted_date=`""+[string]$del_time +"`"" + " File_Hash_MD5=`""+ $mdhash +"`"" + " File_Hash_SHA1=`""+ $shahash +"`"" 
				 
		Write-Host $filedata
		
#		Write-Host "File: $filename `n`tHeader: $header_str `n`tOriginal File Size: $file_size bytes `n`tOriginal File Path: $path_str `n`tDeleted date: $del_time "
	}
	#Windows 7/8
	Elseif ($header_str -match "0100000000000000"){
		$size = (Get-Content -Encoding Byte -path $file)[8 .. 15]
		$file_size = [System.BitConverter]::ToInt64($size,0)
		$temp_time = (Get-Content -Encoding Byte -path $file)[16 .. 23]
		$temp = [System.BitConverter]::ToInt64($temp_time,0)
		$del_time = [DateTime]::FromFileTime($temp)
		#Grab original file location
		$diff = (Get-Item $file).Length
		$orig_path = (Get-Content -Encoding Byte -path $file)[24 .. $diff]
		$path_str = [System.Text.Encoding]::Ascii.GetString($orig_path) -replace "\x00"
		$filename = (Get-Item $file).Name
		$mdhash = Get-MdHash -file $file -size $diff
		$shahash = Get-ShaHash -file $file -size $diff
		
		$filedata = " Filename=`""+[string]$filename+"`""+" Header=`""+[string]$header_str +"`"" +" Original_size=`""+[string]$file_size +"`"" +" Original_file_path=`""+[string]$path_str +"`"" +" Deleted_date=`""+[string]$del_time +"`"" + " File_Hash_MD5=`""+ $mdhash +"`"" + " File_Hash_SHA1=`""+ $shahash +"`""
		
		Write-Host $filedata
		
#		Write-Host "File: $filename `n`tHeader: $header_str `n`tOriginal File Size: $file_size bytes `n`tOriginal File Path: $path_str `n`tDeleted date: $del_time "
	}
	# If the file header does not match an $I file, print name, header, size, location
	Else{
		$file_size = (Get-Item $file).Length
		$filename = (Get-Item $file).Name
		$path_str = (Get-Item $file).FullName
		$mdhash = Get-MdHash -file $file -size $file_size
		$shahash = Get-ShaHash -file $file -size $file_size
		
		$filedata = " Filename=`""+[string]$filename+"`""+" Original_size=`""+[string]$file_size +"`"" +" Original_file_path=`""+[string]$path_str +"`"" + " File_Hash_MD5=`""+ $hash +"`"" + " File_Hash_SHA1=`""+ $shahash +"`""
		
		Write-Host $filedata
		
#		Write-Host "File: $filename	`n`tHeader: $header_str	`n`tSize: $file_size	`n`tPath: $path_str"
	}
	
}

$PATH = 'C' + ':\$Recycle.Bin'
$bin = Get-ChildItem $Path  -Force -Recurse

# Parse through $Path
foreach ($item in $bin){
 $tempr=$item.Attributes
	if ($item.Attributes -notmatch "Directory"){	
		If ($item.Name -match "desktop.ini"){
			continue
		}
		Else{
			$f = $item.FullName
			Get-DeletedMetadata -file $f
		}
	}	
}
