<?php

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

    static function dns(string $dominio, string $type,string $how='ipv4'):array {
        self::$providername='google';
        self::$provider=self::PROVIDER;
        return parent::dns($dominio,$type,$how);
    }
}
