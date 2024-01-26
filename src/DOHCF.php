<?php
declare(strict_types=1);
/**
 * @package DOH
 */
/**
 * DOH resolver that uses CloudFlare as a backend
 */
class DOHCF extends DOHBase {

    /** @ignore */
    private const PROVIDER = [
        'url' => 'https://%s/dns-query?type=%s&name=%s',
        'host' => 'cloudflare-dns.com',
        'ipv4' => ['104.16.248.249', '104.16.249.249'],
        'ipv6' => ['2606:4700::6810:f9f9', '2606:4700::6810:f8f9']
    ];

    /**
     * Execute a DNS query
     * 
     * Inherited from {@see DOHBase::dns}
     * 
     * @param  string $domain Name to resolve
     * @param  string $type Record type to ask for
     * @param string $how (optional) Indicates whether the connection will be via IPv4 or IPv6 (default is IPv4)
     * @return array<string,string>  Query result
     * @throws InvalidArgumentException on no valid parameters
     */
    static function dns(string $domain, string $type, string $how = 'ipv4'): array {
        self::$providername = 'cloudflare';
        self::$provider = self::PROVIDER;
        return parent::dns($domain, $type, $how);
    }
}
