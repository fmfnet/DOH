<?php
declare(strict_types=1);
/**
 * @package DOH
 */
/**
 * DOH resolver that uses Google as a backend
 */
class DOHGG extends DOHBase {

    /** @ignore */
    private const PROVIDER = [
        'url' => 'https://%s/resolve?type=%s&name=%s',
        'host' => 'dns.google',
        'ipv4' => ['8.8.8.8', '8.8.4.4'],
        'ipv6' => ['2001:4860:4860::8888', '2001:4860:4860::8844']
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
        self::$providername = 'google';
        self::$provider = self::PROVIDER;
        return parent::dns($domain, $type, $how);
    }
}
