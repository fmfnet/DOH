<?php
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
 * constant: SIRMONTI_DOH_PROVIDER. If the constant is not provided, 
 * hardcoded default is cloudflare.
 *
 * @author Francisco Monteagudo
 * @version 1.0.0
 * @license https://opensource.org/licenses/MIT (MIT License)
 *
 */
declare(strict_types=1);

namespace sirmonti;

use \Exception;
use \InvalidArgumentException;

class DOH {
    // Default values
    private const DEFPROVIDER='cloudflare';

    // Constants for internal use
    private const NAME='DOHPHPClient/1.0';
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
        'SSHFP'=>44,
        'TLSA'=>52,
        'CAA'=>257
    ];

    private const PROVIDERS=[
        'cloudflare'=>'https://cloudflare-dns.com/dns-query?type=%s&name=%s',
        'google'=>'https://dns.google/resolve?type=%s&name=%s'
    ];

    private int $provid;
    private string $url;
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
            $provider=(defined('SIRMONTI_DOH_PROVIDER')) ? SIRMONTI_DOH_PROVIDER:self::DEFPROVIDER;
        }

        $this->url=(string)@self::PROVIDERS[$provider];
        if($this->url=='')
            throw new InvalidArgumentException('Invalid provider');

    }

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
    }

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

    private function procGEN(array $resp, string $tipo):array
    {
        $idt=self::RECTYPES[$tipo];
        $data=[];
        foreach($resp as $r) {
            if($r->type!=$idt)
                continue;

            if(substr($r->data,0,3)=='\# ') {
                $txt=$this->decode($r->data,$tipo);
                if($txt!='') $data[]=$txt;
            } else $data[]=$r->data;
        }

        return $data;
    }

    /**
     * Execute a DNS query. The query return an array with the responses. In case
     * of error the function returns an empty array and set "status" attribute
     * with the error code.
     * 
     * When parameters have an invalid value, an InvalidValurException will be raised
     * 
     * Valid record types: NS, MX, TXT, A, AAAA, CNAME, SPF, SOA, PTR, SRV
     * 
     * state response codes:
     *
     *    0: OK
     *
     *    1: Empty response. There are not response to this query.
     *
     *    2: The DNS servers for this domain are misconfigured
     *
     *    3: The domain does not exist
     *
     *    4: Network error
     *
     *    5: Lame response
     * 
     * 10XX: Values above 1000 contains error code returned by DNS server
     *
     *  This errors generate an exception of type InvalidArgumentException 
     * 
     *  100: Invalid record type
     * 
     *  101: Invalid IP address
     *
     * @param  string $dominio Dominio a comprobar
     * @param  string $tipo Tipo de registro
     * @return array  array con el resultado de la operación
     * @throws InvalidArgumentException on no valid parameters
     */
    public function dns(string $dominio,string $tipo):array
    {
        $this->status=0;
        if(!isset(self::RECTYPES[$tipo]))
            throw new InvalidArgumentException('Invalid record type',100);
        if($tipo=='PTR') {
            if(preg_match('/^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/',$dominio,$r)) {
                $dominio=sprintf('%d.%d.%d.%d.in-addr.arpa',$r[4],$r[3],$r[2],$r[1]);
            } elseif(filter_var($dominio,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) {
                $d=@unpack('H*',inet_pton($dominio))[1];
                if(strlen($d)!=32) {
                    $this->status=102;
                    throw new InvalidArgumentException('Invalid IP address',101);
                }
                $dominio=implode('.',str_split(strrev($d))).'.ip6.arpa';
            } else {
                $this->status=102;
                throw new InvalidArgumentException('Invalid IP address',101);
            }
        }
        $opts=[
            'http'=>[
                    'method'=>'GET',
                    'header'=>['accept: application/dns-json',
                    'User-Agent: '.self::NAME
                ]
            ]
        ];

        $ctx=stream_context_create($opts);
        $resp=json_decode((string)@file_get_contents(sprintf($this->url,$tipo,urlencode($dominio)),false,$ctx));

        if(!is_object($resp)||!isset($resp->Status)) {
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

        switch($tipo) {
            case 'NS':return $this->procNS($resp->Answer);
            case 'MX':return $this->procMX($resp->Answer);
        }

        return $this->procGEN($resp->Answer,$tipo);
    }
    public function __get($key)
    {
        if($key=='status') return $this->status;
        trigger_error('Undefined property: sirmonti\DOH::$'.$key);
        return null;
    }
};
