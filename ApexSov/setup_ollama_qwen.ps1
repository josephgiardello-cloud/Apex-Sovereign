$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modelfile = Join-Path $scriptDir 'Modelfile.apex-qwen'

Write-Host 'Checking Ollama...'
$null = Get-Command ollama -ErrorAction Stop

Write-Host 'Pulling qwen2.5:7b...'
ollama pull qwen2.5:7b

Write-Host 'Creating apex-qwen alias from Modelfile.apex-qwen...'
ollama create apex-qwen -f $modelfile

Write-Host 'Installed local models:'
ollama list
