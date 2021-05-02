<?php
require_once __DIR__.'/../src/DOH.php';

define('FMFNET_DOH_PROVIDER','cloudflare'); // This constant is optional
$doh = new \fmfnet\DOH('cloudflare'); // The parameter is optional
$resp = $doh->dns('www.google.com','A'); // Query with a single response
echo "Response to A query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);

$resp = $doh->dns('google.com','TXT'); // Query with a multiple response
echo "\nResponse to TXT query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);

$resp = $doh->dns('nonexistentdomain.test','TXT'); // Query with an invalid response
echo "\nResponse to bogus query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);
