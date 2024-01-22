<?php

/**
 * @package Tests
 */
/**
 * Test library using cloudflare DOH backend
 */
require_once __DIR__ . '/../src/DOHBase.php';
require_once __DIR__ . '/../src/DOHGG.php';

$resp = DOHGG::dns('www.google.com', 'A'); // Query with a single response
echo "Response to A query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('google.com', 'TXT'); // Query with a multiple response
echo "\nResponse to TXT query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('nonexistentdomain.test', 'TXT'); // Query with an invalid response
echo "\nResponse to bogus query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('cloudflare.com', 'DS'); // Query for a DNSSEC record
echo "\nReponse to DS query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('cloudflare.com', 'DNSKEY'); // Query for a DNSSEC record
echo "\nReponse to DNSKEY query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('cloudflare.com', 'CAA'); // Query for CAA records
echo "\nResponse to CAA query:\n";
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('23.206.85.57', 'PTR'); // Resolve a IPv4 address
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

$resp = DOHGG::dns('2a02:26f0:980:5bc::8c4', 'PTR'); // Resolve a IPv6 address
print_r($resp);
printf("DNS response status code: %d\n", DOHGG::getStatus());

