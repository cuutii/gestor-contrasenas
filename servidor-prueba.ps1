# Servidor local para probar la Bóveda.
#
# HACE FALTA porque Web Crypto (crypto.subtle) solo funciona en
# contextos seguros: https:// o localhost. Si abrís index.html
# con doble clic (file://) la app se niega a arrancar.
#
#   powershell -ExecutionPolicy Bypass -File servidor-prueba.ps1
#
# y después abrí http://localhost:8127
#
# ⚠️ OJO: esto sirve SOLO para probar en tu compu. Cualquier
# servidor que no sea localhost inseguro rompe la seguridad de
# la bóveda entera: el navegador bajaría el JS por http y un
# intermediario podría reemplazar el código.
$puerto = 8127
$raiz = $PSScriptRoot

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$puerto/")
$listener.Start()
Write-Host "Bóveda en http://localhost:$puerto  (Ctrl+C para cortar)"

$mime = @{
  ".html" = "text/html; charset=utf-8"
  ".css"  = "text/css; charset=utf-8"
  ".js"   = "application/javascript; charset=utf-8"
  ".json" = "application/json"
  ".md"   = "text/markdown; charset=utf-8"
  ".svg"  = "image/svg+xml"
  ".png"  = "image/png"
}

while ($listener.IsListening) {
  $ctx = $listener.GetContext()
  $ruta = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath).TrimStart("/")
  if ([string]::IsNullOrEmpty($ruta)) { $ruta = "index.html" }

  $archivo = Join-Path $raiz $ruta

  # No salirse de la carpeta: corta ../ etc.
  $full = [IO.Path]::GetFullPath($archivo)
  if (-not $full.StartsWith([IO.Path]::GetFullPath($raiz))) {
    $ctx.Response.StatusCode = 403
    $ctx.Response.Close()
    continue
  }

  if (Test-Path $archivo -PathType Leaf) {
    $ext = [IO.Path]::GetExtension($archivo).ToLower()
    $tipo = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { "application/octet-stream" }
    $bytes = [IO.File]::ReadAllBytes($archivo)
    $ctx.Response.StatusCode = 200
    $ctx.Response.ContentType = $tipo
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  } else {
    $ctx.Response.StatusCode = 404
  }
  $ctx.Response.Close()
}
