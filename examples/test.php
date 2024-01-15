<?php
require_once __DIR__.'/../src/DOH.php';

$doh = new DOH('cloudflare'); // The parameter is optional
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

$resp = $doh->dns('cloudflare.com','DS'); // Query for a DNSSEC record
echo "\nReponse to DS query:\n";
print_r($resp);

$resp = $doh->dns('cloudflare.com','DNSKEY'); // Query for a DNSSEC record
echo "\nReponse to DNSKEY query:\n";
print_r($resp);

