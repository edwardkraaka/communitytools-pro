<?php
// php2shell lab harness — minimal upstream-derived target app.
// From php2shell-poc (github.com/ikow/php2shell-poc, MIT) at commit
// 31519e6d8a84dee1df1262961ed1bebb65accadd. This file is a TEST TARGET, not
// an exploit: it only exposes the default-PHP conditions the CVEs require
// (session_start on every request, session.upload_progress at defaults).
//
// Deliberately stock PHP configuration is the point: the vulnerability lives
// in the engine's rfc1867 handler + Zend OOM bailout, not in app code.

session_start();  // producer/consumer precondition for chain E (FPM)

header('Content-Type: text/html; charset=utf-8');
echo "<!DOCTYPE html><html><head><title>upload test</title></head><body>\n";
echo "<h1>php2shell lab target</h1>\n";

// Reflect the upload (as any PHP app with a form endpoint would). The
// rfc1867 upload_progress handler has ALREADY run during SAPI parsing —
// before this line — which is exactly the pre-auth window the CVEs abuse.
if (!empty($_FILES)) {
    echo "<p>upload received: " . htmlspecialchars($_FILES['f']['name'] ?? '') . "</p>\n";
}

// Session-content reflection lets tools verify the session-write primitive
// (tier 3 marker read-back) without any exploit code.
if (isset($_GET['dump_session']) && $_GET['dump_session'] === '1') {
    echo "<pre>" . htmlspecialchars(print_r($_SESSION, true)) . "</pre>\n";
}

echo "</body></html>\n";
