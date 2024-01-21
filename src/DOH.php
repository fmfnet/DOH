<?php
declare(strict_types=1);
/**
 * This class implements a DNS resolver that asks a DNS over HTTPS service instead of a regular DNS server.
 * 
 * The constructor accept one parameter: The DNSoverHTTPS provider.
 * Actually, there are two possible providers: "cloudflare" and "google".
 * 
 * DNS over HTTPS client library
 * 
 * If not parameter is provided, default one will be used.
 * 
 * The default DNSoHTTPS provider can be supplied with an optional global
 * constant: DOH_PROVIDER. If the constant is not provided, 
 * hardcoded default is cloudflare.
 *
 * @see https://github.com/sirmonti/doh/ DOH github project
 * 
 * @author Francisco Monteagudo <francisco@monteagudo.net>
 * @version 2.5.0
 * @license https://opensource.org/licenses/MIT (MIT License)
 * @copyright (c) 2024, Francisco Monteagudo
 *
 * @property-read int $status Get the status code for the last operation
 */
class DOH {
    /**
     * Default DOH provider. Valid values are "cloudflare" or "google".
     * You can edit this constant, but we recommend to use the global
     * DOH_PROVIDER constant.
     */
    const DEFPROVIDER='cloudflare';

    // Constants for internal use
    /** @ignore */
    private const NAME='DOHPHPClient/2.5';

    /** @ignore */
    private const PROVIDERS = [
        'cloudflare'=>[
            'url' => 'https://%s/dns-query?type=%s&name=%s',
            'host' => 'cloudflare-dns.com',
            'ipv4' => ['104.16.248.249', '104.16.249.249'],
            'ipv6' => ['2606:4700::6810:f9f9', '2606:4700::6810:f8f9']
        ],
        'google'=>[
            'url' => 'https://%s/resolve?type=%s&name=%s',
            'host' => 'dns.google',
            'ipv4' => ['8.8.8.8', '8.8.4.4'],
            'ipv6' => ['2001:4860:4860::8888', '2001:4860:4860::8844']
        ]
    ];

    /** @ignore */
    private const RECTYPES=[
        'A'=>1,
        'NS'=>2,
        'CNAME'=>5,
        'SOA'=>6,
        'PTR'=>12,
        'MX'=>15,
        'TXT'=>16,
        'AAAA'=>28,
        'SRV'=>33,
        'DS'=>43,
        'SSHFP'=>44,
        'DNSKEY'=>48,
        'TLSA'=>52,
        'CAA'=>257
    ];

    /** @ignore */
    private const DSALGONAMES=[
        'DELETE','RSAMD5','DH','DSA','RSASHA1','DSA-NSEC3-SHA1',
        'RSASHA1-NSEC3-SHA1','RSASHA256','RSASHA512','ECC-GOST',
        'EC3P256SHA256','EC3P384SHA384','ED25519','ED448'
    ];
    /** @ignore */
    private const DSALGOIDS=[0,1,2,3,5,6,7,8,10,12,13,14,15,16];

    /** @ignore */
    private string $provider;
    /** @ignore */
    private array $pdata;
    /** @ignore */
    private int $status;

    /**
     * Build DOH object
     * 
     * @param string $provider (optional) DNS over HTTPS provider to use
     * @throws InvalidArgumentException if the $provider contains an invalid value
     */
    function __construct(string $provider='')
    {
        if($provider=='') {
            $provider=(defined('DOH_PROVIDER')) ? DOH_PROVIDER:self::DEFPROVIDER;
        }
        $this->pdata=(array)@self::PROVIDERS[$provider];
        if(count($this->pdata)==0)
            $this->pdata=(array)@self::PROVIDERS[self::DEFPROVIDER];
        if(count($this->pdata)==0)
            throw new InvalidArgumentException (_('Invalid DOH provider'));
        $this->provider=$provider;
    }

    /** @ignore */
    private function decode(string $data,string $type):string
    {
        if(!preg_match('/^\\\# [0-9a-fA-F]+ (.+)$/',$data,$info))
            return '';
        $tmp=explode(' ',$info[1]);
        switch($type) {
            case 'CAA':
                $f=hexdec($tmp[0]);
                $t=hexdec($tmp[1]);
                $idtmp=array_slice($tmp,2,$t);
                array_splice($tmp,0,$t+2);
                array_walk($idtmp,function(&$val,$idx) {$val=chr(hexdec($val));});
                array_walk($tmp,function(&$val,$idx) {$val=chr(hexdec($val));});
                $idtmp=implode('',$idtmp);
                $tmp=implode('',$tmp);
                return sprintf('%d %s "%s"',$f,$idtmp,$tmp);
            case 'TLSA':
                $v1=hexdec($tmp[0]);
                $v2=hexdec($tmp[1]);
                $v3=hexdec($tmp[2]);
                return sprintf('%d %d %d %s',$v1,$v2,$v3,implode('',array_slice($tmp,3)));
        }
        return '';
    }

    /** @ignore */
    private function procNS(array $resp):array
    {
        $data=[];
        foreach($resp as $r) {
            if($r->type!=2)
                continue;

            $host=$r->data;
            if(substr($host,-1)=='.')
                    $host=substr($host,0,strlen($host)-1);

            $data[]=$host;
        }

        return $data;
    }

    /** @ignore */
    private function procMX(array $resp):array
    {
        $data=[];
        foreach($resp as $r) {
            if($r->type!=15)
                continue;

            [$prio,$host]=explode(' ',$r->data);
            if(substr($host,-1)=='.')
                    $host=substr($host,0,strlen($host)-1);

            $data[]=$prio.' '.$host;
        }

        return $data;
    }

    /** @ignore */
    private function procKEYS(array $resp):array {
        $data=[];
        foreach($resp as $r) {
            switch($r->type) {
                case 43:
                case 48:
                    $data[]=str_replace(self::DSALGONAMES,self::DSALGOIDS,$r->data);
                    break;
            }
        }
        return $data;
    }

    /** @ignore */
    private function procGEN(array $resp, string $type):array
    {
        $idt=self::RECTYPES[$type];
        $data=[];
        foreach($resp as $r) {
            if($r->type!=$idt)
                continue;

            if(substr($r->data,0,3)=='\# ') {
                $txt=$this->decode($r->data,$type);
                if($txt!='') $data[]=$txt;
            } else $data[]=$r->data;
        }

        return $data;
    }

    /**
     * Convert an IPv4 or IPv6 address to a DNS name valid for a PTR request.
     * 
     * This is a static function, so it can be used independently
     * 
     * @param string $ip IP address to convert
     * @return string DNS name representing the IP
     */
    static function IPtoDNS(string $ip):string {
        if(preg_match('/^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/',$ip,$r)) {
            $dns=sprintf('%d.%d.%d.%d.in-addr.arpa',$r[4],$r[3],$r[2],$r[1]);
        } elseif(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) {
            $d=@unpack('H*',inet_pton($ip))[1];
            if(strlen($d)!=32) {
                return '';
            }
            $dns=implode('.',str_split(strrev($d))).'.ip6.arpa';
        } else {
            return '';
        }
        return $dns;
    }

    /**
     * Get the status code for the last query
     * 
     * @return int The status code for the last query
     */
    function getStatus():int {
        return $this->status;
    }
    /**
     * Execute a DNS query. The query return an array with the responses. In case
     * of error the function returns an empty array and set "status" attribute
     * with the error code.
     * 
     * When parameters have an invalid value, an InvalidValurException will be raised
     * 
     * Valid record types: NS, MX, TXT, A, AAAA, CNAME, SPF, SOA, PTR, SRV, DS, DNSKEY
     * 
     * state response codes:
     *
     *    - 0: OK
     *    - 1: Empty response. There are not response to this query.
     *    - 2: The DNS servers for this domain are misconfigured
     *    - 3: The domain does not exist
     *    - 4: Network error
     *    - 5: Lame response
     *  - 101: Invalid IP address provided
     * - 10XX: Values above 1000 contains error code returned by DNS server
     *
     *  This errors generate an exception of type InvalidArgumentException with
     * the following codes:
     * 
     *  - 100: Invalid record type
     *  - 101: Invalid IP address
     *
     * @param  string $dominio Name to resolver
     * @param  string $type Register type
     * @return array<string,string>  array Query result
     * @throws InvalidArgumentException on no valid parameters
     */
    public function dns(string $dominio,string $type):array
    {
        $this->status=0;
        if(!isset(self::RECTYPES[$type])) {
            $this->status=100;
            throw new InvalidArgumentException(_('Invalid record type'),100);
        }
        if($type=='PTR') {
            $dominio=$this->IPtoDNS($dominio);
            if($dominio=='') {
                $this->status=101;
                throw new InvalidArgumentException(_('Invalid IP address'),101);
            }
        }
        $opts=[
            'http'=>[
                    'ignore_errors'=>true,
                    'method'=>'GET',
                    'header'=>['accept: application/dns-json',
                    'User-Agent: '.self::NAME,
                    'Host: '.$this->pdata['host']
                ]
            ],
            'ssl'=>[
                'SNI_enabled'=>true,
                'peer_name'=>$this->pdata['host']
            ]
        ];

        $ips=$this->pdata['ipv4'];
        $ip=$ips[mt_rand(0,count($ips)-1)];
        $ctx=stream_context_create($opts);
        $resp=json_decode((string)@file_get_contents(sprintf($this->pdata['url'],$ip,$type,urlencode($dominio)),false,$ctx));
        if(!is_object($resp)||!isset($resp->Status)||(!is_array($http_response_header))) {
            $this->status=4;
            return [];
        }
        if(!preg_match('/^HTTP\/[0-9]+\.[0-9]+\ ([0-9]{3})\ (.+)$/', $http_response_header[0], $status)) {
            $this->status=4;
            return [];
        }
        if((int)@$status[1]!=200) {
            $this->status=4;
            return [];
        }
        if($resp->Status!=0) {
            switch($resp->Status) {
                case 2:
                case 3:
                    $this->status=$resp->Status;
                    return [];
            }
            $this->status=$resp->Status+1000;
        }

        if(!isset($resp->Answer)) {
            $this->status=1;
            return [];
        }

        switch($type) {
            case 'NS':return $this->procNS($resp->Answer);
            case 'MX':return $this->procMX($resp->Answer);
            case 'DS':
            case 'DNSKEY':
                if($this->provider=='cloudflare')
                    return $this->procKEYS($resp->Answer);
                break;
        }

        return $this->procGEN($resp->Answer,$type);
    }

    /** @ignore */
    public function __get($key)
    {
        if($key=='status') return $this->status;
        trigger_error('Undefined property: DOH::$'.$key);
        return null;
    }
};
