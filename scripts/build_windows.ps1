param([string]$OutputDirectory = 'release')

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) { throw '先运行 python -m venv .venv' }
& $pythonExe -m pip install -r desktop/requirements.txt
if ($LASTEXITCODE -ne 0) { throw '桌面依赖安装失败' }
Push-Location frontend
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw '前端依赖安装失败' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw '前端构建失败' }
} finally { Pop-Location }
& $pythonExe -m PyInstaller --noconfirm --clean --onefile --windowed --name AutoMiner --distpath $OutputDirectory --workpath build --specpath build --paths "$projectRoot/backend" --paths $projectRoot --add-data "$projectRoot/frontend/dist;frontend/dist" --hidden-import app.main --collect-submodules uvicorn --collect-all webview --hidden-import sqlalchemy.dialects.sqlite --exclude-module pytest --exclude-module psycopg desktop/launcher.py
if ($LASTEXITCODE -ne 0) { throw 'EXE 打包失败' }
$smokeDirectory = Join-Path $projectRoot ('build\packaged-smoke-' + [guid]::NewGuid().ToString('N'))
$resultFile = Join-Path $projectRoot 'build\last-packaged-smoke.json'
$smokeProcess = Start-Process -FilePath (Join-Path $projectRoot (Join-Path $OutputDirectory 'AutoMiner.exe')) -ArgumentList @('--smoke-test','--data-dir',('"' + $smokeDirectory + '"'),'--result-file',('"' + $resultFile + '"')) -WindowStyle Hidden -PassThru
if (-not $smokeProcess.WaitForExit(60000)) {
    Stop-Process -Id $smokeProcess.Id
    throw 'EXE 自检超时'
}
$smokeProcess.Refresh()
if ($smokeProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultFile)) { throw 'EXE 自检失败，请检查 build 下的日志' }
$result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
if (-not $result.ok) { throw 'EXE 自检失败' }
Write-Host "已生成并通过实际请求自检：$OutputDirectory\AutoMiner.exe"
