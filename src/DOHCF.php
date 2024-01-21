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
     * 
     * @param string $dominio
     * @param string $type
     * @param string $how
     * @return array
     */
    static function dns(string $dominio, string $type,string $how='ipv4'): array {
        self::$providername='cloudflare';
        self::$provider = self::PROVIDER;
        return parent::dns($dominio, $type,$how);
    }
}
