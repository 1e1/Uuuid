<?php
/**
 * Created by PhpStorm.
 * User: AyGLR
 * Date: 26/02/16
 * Time: 19:17.
 */

namespace Hoathis\Uuuid;

final class Uuid
{
    const SEP = '-';

    public static $SALT = '$@1†';

    /**
     * @var string
     */
    protected $uuid;

    /** @var bool */
    protected $isValid;

    /**
     * @var array
     */
    private $_cache;

    /**
     * generate an empty UUID.
     */
    public function __construct()
    {
        $this->uuid = null;
        $this->_cache = null;
        $this->isValid = false;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->uuid;
    }

    /**
     * import from the RFC 4122 format.
     *
     * @param string $uuid
     * @param string $sep
     *
     * @return self
     */
    public function fromHex(string $uuid, string $sep = self::SEP): self
    {
        $this->uuid = filter_var($uuid, FILTER_VALIDATE_REGEXP, [
            'options' => [
                'default' => null,
                'regexp' => '#[0-9a-f]{8}(?:'.$sep.'[0-9a-f]{4}){4}[0-9a-f]{4}#',
            ],
        ]);

        $this->isValid = $this->_cache();

        return $this;
    }

    /**
     * export to RFC 4122 format.
     *
     * @param string $sep
     *
     * @return string
     */
    public function toHex(string $sep = self::SEP): string
    {
        return self::expand($this->uuid, $sep);
    }

    /**
     * import from internal B64 format.
     *
     * @param string $string
     *
     * @return self
     */
    public function fromBase64(string $string): self
    {
        $this->uuid = null;

        $iso = str_pad($string, 4 - (strlen($string) % 4), '=');
        $b64 = str_replace(['-', '_'], ['+', '/'], $iso);
        $bin = base64_decode($b64);
        $hex = bin2hex($bin);
        if (false !== ($uuid = filter_var($hex, FILTER_VALIDATE_REGEXP, [
                'options' => [
                    'regexp' => '#[a-z0-9]{32}#',
                ],
            ]))
        ) {
            $this->uuid = $uuid;
        }

        $this->isValid = $this->_cache();

        return $this;
    }

    /**
     * export to internal B64 format.
     *
     * @return string
     */
    public function toBase64(): string
    {
        $b64 = base64_encode(hex2bin($this->uuid));
        $iso = str_replace(['+', '/'], ['-', '_'], $b64);

        return rtrim($iso, '=');
    }

    /**
     * generate a new UUID.
     *
     * @param int    $typeId  [0..65535]
     * @param string $binhash optional binary hash
     *
     * @return self
     */
    public function generate(int $typeId, string $binhash = null): self
    {
        $this->_cache = [
            'timestamp' => time(),
            'type' => $typeId % 0x10000,
            'rand' => mt_rand(0, 0xffff),
            'hash' => $binhash ?? openssl_random_pseudo_bytes(12),
        ];

        $this->uuid = sprintf(
            '%08x%04x%04x%04x%012s',
            $this->_cache['timestamp'],
            $this->_cache['type'],
            $this->crc32() % 0x10000,
            $this->_cache['rand'],
            substr(bin2hex($this->_cache['hash']), 0, 12)
        );

        $this->isValid = true;

        return $this;
    }

    /**
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }

    /**
     * @return int
     */
    public function getTimestamp(): int
    {
        return $this->_cache['timestamp'];
    }

    /**
     * @return int
     */
    public function getType(): int
    {
        return $this->_cache['type'];
    }

    /**
     * @return int
     */
    public function getCrc32(): int
    {
        return $this->_cache['crc32'];
    }

    /**
     * @return int
     */
    public function getRand(): int
    {
        return $this->_cache['rand'];
    }

    /**
     * @return string
     */
    public function getHash(): string
    {
        return $this->_cache['hash'];
    }

    /**
     * crc32.
     *
     * @return string
     */
    public function crc32(): string
    {
        return (int) hash('crc32', implode(self::$SALT, $this->_cache));
    }

    /**
     * generate cache info.
     *
     * @return bool
     */
    private function _cache(): bool
    {
        $timestamp = substr($this->uuid, 0, 8);
        $type = substr($this->uuid, 9, 4);
        $crc32 = substr($this->uuid, 14, 4);
        $rand = substr($this->uuid, 19, 4);
        $hash = substr($this->uuid, 24, 12);

        $this->_cache = [
            'timestamp' => (int) hex2bin($timestamp),
            'type' => (int) hex2bin($type),
            'crc32' => (int) hex2bin($crc32),
            'rand' => (int) hex2bin($rand),
            'hash' => hex2bin($hash),
        ];

        return $crc32 === $this->crc32();
    }

    /**
     * add '-' at correct positions in the UUID.
     *
     * @param string $uuid
     * @param string $sep
     *
     * @return string
     */
    protected static function expand(string $uuid, string $sep): string
    {
        return substr($uuid, 0, 8)
        .$sep.substr($uuid, 8, 4)
        .$sep.substr($uuid, 12, 4)
        .$sep.substr($uuid, 16, 4)
        .$sep.substr($uuid, 20, 12);
    }

    /**
     * remove '-' from the UUID.
     *
     * @param string $uuid
     * @param string $sep
     *
     * @return string
     */
    protected static function collapse(string $uuid, string $sep): string
    {
        return str_replace($sep, null, $uuid);
    }
}
