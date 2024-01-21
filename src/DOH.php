<?php

declare(strict_types=1);

/**
 * Wrapper class to provide compatibility with old software
 * 
 * @property-read int $status Status code for the last query. Deprecated, use instead {@see DOH::getStatus()}
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

    /**
     * Build DOH object
     * 
     * @param string $provider (optional) DNS over HTTPS provider to use
     * @throws InvalidArgumentException if the $provider contains an invalid value
     */
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
     * Convert IP address to a DNS representation
     * 
     * Inhrerited from {@see DOHBase::IPtoDNS()}
     * 
     * @param string $ip IP address to convert
     * @return string DNS name representing the IP
     */
    static function iPtoDNS(string $ip): string {
        return DOHBase::IPtoDNS($ip);
    }

    /**
     * Execute a DNS query
     * 
     * Inherited from {@see DOHBase::dns()}
     * 
     * @param  string $domain Name to resolve
     * @param  string $type Record type to ask for
     * @param string $how (optional) Indicates whether the connection will be via IPv4 or IPv6 (default is IPv4)
     * @return array<string,string>  array con el resultado de la operación
     * @throws InvalidArgumentException on no valid parameters
     */
    function dns(string $domain, string $type, string $how = 'ipv4'): array {
        if ($this->provider == 'google') {
            return DOHGG::dns($domain, $type, $how);
        }
        return DOHCF::dns($domain, $type, $how);
    }

    /**
     * Get the status for the last DNS query
     * 
     * Inhrerited from {@see DOHBase::getStatus()}
     * 
     * @return int Status for the last query
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
