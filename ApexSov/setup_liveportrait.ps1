param(
    [string]$ComfyUiDir = "$PSScriptRoot\..\comfyui",
    [string]$WorkflowPath = "$PSScriptRoot\workflows\liveportrait_audio_template.json"
)

$ErrorActionPreference = "Stop"

Write-Host "== DadBot Sovereign LivePortrait Setup ==" -ForegroundColor Cyan

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required but not found in PATH."
}

if (-not (Test-Path $ComfyUiDir)) {
    Write-Host "Cloning ComfyUI into $ComfyUiDir" -ForegroundColor Yellow
    git clone https://github.com/comfyanonymous/ComfyUI.git $ComfyUiDir
}
else {
    Write-Host "ComfyUI already present at $ComfyUiDir" -ForegroundColor Green
}

$customNodesDir = Join-Path $ComfyUiDir "custom_nodes"
if (-not (Test-Path $customNodesDir)) {
    New-Item -ItemType Directory -Path $customNodesDir | Out-Null
}

$nodes = @(
    @{ Name = "ComfyUI-LivePortraitKJ"; Repo = "https://github.com/kijai/ComfyUI-LivePortraitKJ.git" },
    @{ Name = "ComfyUI-VideoHelperSuite"; Repo = "https://github.com/Kosinkadink/ComfyUI-VideoHelperSuite.git" },
    @{ Name = "ComfyUI-AdvancedLivePortrait"; Repo = "https://github.com/PowerHouseMan/ComfyUI-AdvancedLivePortrait.git" }
)

foreach ($node in $nodes) {
    $target = Join-Path $customNodesDir $node.Name
    if (-not (Test-Path $target)) {
        Write-Host "Installing node: $($node.Name)" -ForegroundColor Yellow
        git clone $node.Repo $target
    }
    else {
        Write-Host "Node already installed: $($node.Name)" -ForegroundColor Green
    }
}

$requirementsPath = Join-Path $ComfyUiDir "requirements.txt"
if (Test-Path $requirementsPath) {
    Write-Host "Installing ComfyUI Python dependencies..." -ForegroundColor Yellow
    & "$PSScriptRoot\..\.venv\Scripts\python.exe" -m pip install -r $requirementsPath
}

Write-Host "" 
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1) Launch ComfyUI: python main.py --listen 127.0.0.1 --port 8188 (from ComfyUI dir)"
Write-Host "2) Export a working LivePortrait workflow JSON from ComfyUI"
Write-Host "3) Ensure the JSON contains token placeholders:"
Write-Host "   __SOURCE_IMAGE__, __DRIVING_AUDIO__, __OUTPUT_BASENAME__"
Write-Host "4) Save workflow to: $WorkflowPath"
Write-Host "5) In Streamlit sidebar set Avatar source to 'Generated (TTS + LivePortrait)'"
Write-Host "" 
Write-Host "Optional env vars:" -ForegroundColor Cyan
Write-Host "  APEX_LIVEPORTRAIT_WORKFLOW=<workflow-json-path>"
Write-Host "  APEX_TTS_PIPER_EXE=<path-to-piper.exe>"
Write-Host "  APEX_TTS_PIPER_MODEL=<path-to-piper-model.onnx>"
