<?php

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
     * @see DOHBase::dns
     * 
     * @param string $domain Name to resolve
     * @param string $type Record type
     * @param string $how (optional) Ask vía IPv4 or IPv6 (Default via IPv4)
     * @return array
     */
    static function dns(string $dominio, string $type, string $how = 'ipv4'): array {
        self::$providername = 'cloudflare';
        self::$provider = self::PROVIDER;
        return parent::dns($dominio, $type, $how);
    }
}
