# simple Flask starter
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Set-Location "D:\NIS_PROJECT"
.\.venv\Scripts\Activate.ps1
python app.py
Write-Host "`nPress Enter to close this window..."
Read-Host | Out-Null
