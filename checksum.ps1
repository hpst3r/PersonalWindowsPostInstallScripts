param (
    [String]$hash,
    [String]$algorithm,
    [String]$path
)

if ((Get-FileHash -Path $path -Algorithm $algorithm).Hash = $hash) {
    return True
} else {
    return False
}