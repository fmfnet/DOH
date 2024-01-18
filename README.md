# DOH - DNS over HTTPS client library for PHP
---

[![Version](https://poser.pugx.org/sirmonti/doh/version)](//packagist.org/packages/sirmonti/doh)
[![License](https://poser.pugx.org/sirmonti/doh/license)](//packagist.org/packages/sirmonti/doh)

## Introduction
---
DNS resolve is a well known function that is implemented in all operating systems, then, Why we need a different way to do it?
The main reason is privacy, standard DNS protocol don't encrypt connections, which means DNS requests can be spied and forged.

But there are other reasons; first, DOH is very fast, more fast than a lot of local servers. This is not very surprisingly if you consider that cloudflare
and google (the main DOH providers) have huge network infraestructures. But there are more, DOH provides a more descriptive errors. For example,
standard DNS servers can misinterpret network errors as nonexistent records. DOH will correctly report the error.

If you need a fast and reliable DNS name resolution, DOH provides a better solution than standard DNS servers.

## Install
---
Vía composer

``` bash
$ composer require sirmonti/doh
```

## Usage
---
Actually, the library supports two DoH providers: "cloudflare" and "google".
The providers are accessed through these URIs:
- cloudflare: https://cloudflare-dns.com/dns-query
- google: https://cloudflare-dns.com/dns-query

Functions and parameters:

|function|Description|
|---|---|
|DOH_PROVIDER|Optional global constant to define a default provider|
|contructor($provider)|Create DOH object. The optional parameter "$provider" can be "cloudflare" or "google"|
|dns($name,$type)|Resolve a DNS query. $name is the name to resolve and $type is the record type searched|
|$status|This property stores the status code for the last operation|

The DoH provider is taken in this order:
- The constructor parameter
- The global constant DOH_PROVIDER
- The hardcoded default (Actually, "cloudflare"). Can be changed
  editing the class constant DEFPROVIDER in the source code

## DNS resolution
---
The method "dns($name,$type)" execute a DNS query. The query return an array with the
responses. In case of error the function returns an empty array and set "status"
attribute with the error code. The parameters are the name we want resolve
and the record type we are asking for.

When parameters have an invalid value, an InvalidValurException will be raised

Valid record types: NS, MX, TXT, A, AAAA, CNAME, SPF, SOA, PTR, SRV, DS, DNSKEY

The response is an array with the returned responses. If the query don't have a
valid response or an error ocurrs, the call will return an empty array and set
the "status" property to the error code. If all is ok, the status code will be zero.

state code values:
    - 0: OK
    - 1: Empty response. There are not response to this query.
    - 2: The DNS servers for this domain are misconfigured
    - 3: The domain does not exist
    - 4: Network error
    - 5: Lame response
 - 10XX: Values above 1000 contains error code returned by DNS server

## Examples
---
```php
$doh = new DOH('cloudflare'); // Will use cloudflare as resolver
$resp = $doh->dns('www.google.com','A'); // Query with a single response
echo "\nResponse A query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);
```

The script produces this response
```
Response to A query:
Array
(
    [0] => 142.250.200.68
)
DNS response status code: 0
```
In this example, we use the DOH_PROVIDER constant to set the resolver

```php
define('DOH_PROVIDER','google');
$doh=new DOH;
$resp = $doh->dns('google.com','TXT'); // Query with a multiple response
echo "\nResponse TXT query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);
```
The script produces this response
```
Response to TXT query:
Array
(
    [0] => "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
    [1] => "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
    [2] => "v=spf1 include:_spf.google.com ~all"
    [3] => "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
    [4] => "apple-domain-verification=30afIBcvSuDV2PLX"
    [5] => "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
    [6] => "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
    [7] => "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
    [8] => "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
)
DNS response status code: 0
```

Example for a bogus query. We use the hardcoded default resolver
```php
$doh=new DOH;
$resp = $doh->dns('nonexistentdomain.test','TXT'); // Query with an invalid response
echo "\nResponse TXT query:\n";
print_r($resp);
printf("DNS response status code: %d\n",$doh->status);
```
The script produces this response
```
Response to bogus query:

Array
(
)
DNS response status code: 3
```

## LICENSE
---
This library is licensed under [MIT LICENSE](LICENSE)
