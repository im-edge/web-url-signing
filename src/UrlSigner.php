<?php

namespace IMEdge\Web\UrlSigning;

use gipfl\IcingaWeb2\Url;

class UrlSigner
{
    protected string $key;
    protected string $paramExpires = 'expires';
    protected string $paramSignature = 'signature';
    protected string $paramSignedAt = 'signedAt';
    protected array $ignoreParams;

    public function __construct(string $key, array $ignoreParams = [])
    {
        $this->key = $key;
        $this->ignoreParams = $ignoreParams;
        $this->ignoreParams[] = $this->paramExpires;
        $this->ignoreParams[] = $this->paramSignature;
        $this->ignoreParams[] = $this->paramSignedAt;
    }

    public function sign(Url $url, int $expiration): Url
    {
        $signature = self::createSignature($url->without($this->ignoreParams), $expiration, $this->key);

        return $url->with([
            $this->paramSignedAt => time(),
            $this->paramExpires => $expiration,
            $this->paramSignature => $signature,
        ]);
    }

    public function validate(Url $url): bool
    {
        $expiration = $url->getParam($this->paramExpires);
        if ($expiration === null || $expiration < time()) {
            return false;
        }
        $signature = $url->getParam($this->paramSignature);
        if ($signature === null) {
            return false;
        }

        return $this->signatureIsValid($url, $expiration, $signature);
    }

    protected function signatureIsValid(Url $url, int $expiration, string $signature): bool
    {
        $validSignature = self::createSignature($url->without($this->ignoreParams), $expiration, $this->key);
        return hash_equals($validSignature, $signature);
    }

    protected static function createSignature(Url $url, string $expiration, string $key): string
    {
        return hash_hmac('sha256', $url->getAbsoluteUrl() . "::$expiration", $key);
    }
}
