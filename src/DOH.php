<?php

declare(strict_types=1);

/**
 * Wrapper class to provide compatibility with old software
 */
class DOH {

    /**
     * Default DOH provider. Valid values are "cloudflare" or "google".
     * You can edit this constant, but we recommend to use the global
     * DOH_PROVIDER constant.
     */
    const DEFPROVIDER = 'cloudflare';

    /** @ignore */
    private string $provider;

    function __construct(string $provider) {
        if ($provider == '') {
            $provider = (defined('DOH_PROVIDER')) ? DOH_PROVIDER : self::DEFPROVIDER;
        }
        switch ($provider) {
            case 'cloudflare':
            case 'google':
                $this->provider = $provider;
                break;
            default:
                throw new InvalidArgumentException(_('Invalid DOH provider'));
        }
    }

    /**
     * @see DOHBase::IPtoDNS
     */
    static function iPtoDNS(string $ip): string {
        return DOHBase::IPtoDNS($ip);
    }

    /**
     * @see DOHBase::dns
     */
    function dns(string $domain, string $type, string $how = 'ipv4'): array {
        if ($this->provider == 'google') {
            return DOHGG::dns($domain, $type, $how);
        }
        return DOHCF::dns($domain, $type, $how);
    }

    /**
     * @see DOHBase::getStatus
     */
    function getStatus(): int {
        if ($this->provider == 'google') {
            return DOHGG::getStatus();
        }
        return DOHCF::getStatus();
    }

    /** @ignore */
    function __get(string $key) {
        if ($key == 'status')
            return $this->getStatus();
        trigger_error('Undefined property: DOH::$' . $key);
    }
}
