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
    public function __toString()
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
    public function fromHex($uuid, $sep = self::SEP)
    {
        $this->uuid = filter_var($uuid, FILTER_VALIDATE_REGEXP, [
            'options' => [
                'default' => null,
                'regexp' => '#[0-9a-f]{8}(?:'.$sep.'[0-9a-f]{4}){4}[0-9a-f]{4}#',
            ],
        ]);

        $this->uuid = str_replace($sep, null, $this->uuid);

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
    public function toHex($sep = self::SEP)
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
    public function fromBase64($string)
    {
        $this->uuid = null;
        $replacements = [
            '-' => '+',
            '_' => '/',
        ];

        $iso = str_pad($string, 4 - (strlen($string) % 4), '=');
        $b64 = strtr($iso, $replacements);
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
    public function toBase64()
    {
        $replacements = [
            '+' => '-',
            '/' => '_',
        ];

        $b64 = base64_encode(hex2bin($this->uuid));
        $iso = strtr($b64, $replacements);

        return rtrim($iso, '=');
    }

    /**
     * generate a new UUID.
     *
     * @param int    $typeId [0..65535]
     * @param string $bin    optional binary hash
     *
     * @return self
     */
    public function generate($typeId, $bin = null)
    {
        $randomBytes = null === $bin
            ? openssl_random_pseudo_bytes(12)
            : $bin;

        $hash = bin2hex($randomBytes);

        $this->_cache = [
            'timestamp' => time(),
            'type' => $typeId % 0x10000,
            'rand' => mt_rand(0, 0xffff),
            'hash' => substr($hash, 0, 12),
            'crc32' => $this->crc32() % 0x10000,
        ];

        $this->uuid = sprintf(
            '%08x%04x%04x%04x%012s',
            $this->_cache['timestamp'],
            $this->_cache['type'],
            $this->_cache['crc32'],
            $this->_cache['rand'],
            $this->_cache['hash']
        );

        $this->isValid = true;

        return $this;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return $this->isValid;
    }

    /**
     * @return int
     */
    public function getTimestamp()
    {
        return $this->_cache['timestamp'];
    }

    /**
     * @return int
     */
    public function getType()
    {
        return $this->_cache['type'];
    }

    /**
     * @return int
     */
    public function getCrc32()
    {
        return $this->_cache['crc32'];
    }

    /**
     * @return int
     */
    public function getRand()
    {
        return $this->_cache['rand'];
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->_cache['hash'];
    }

    /**
     * crc32.
     *
     * @return string
     */
    public function crc32()
    {
        $copy = [
            $this->_cache['timestamp'],
            $this->_cache['type'],
            $this->_cache['rand'],
            $this->_cache['hash'],
        ];

        return (int) hash('crc32', implode(self::$SALT, $copy));
    }

    /**
     * generate cache info.
     *
     * @return bool
     */
    private function _cache()
    {
        $timestamp = substr($this->uuid, 0, 8);
        $type = substr($this->uuid, 8, 4);
        $crc32 = substr($this->uuid, 12, 4);
        $rand = substr($this->uuid, 16, 4);
        $hash = substr($this->uuid, 20, 12);

        $this->_cache = [
            'timestamp' => (int) hexdec($timestamp),
            'type' => (int) hexdec($type),
            'crc32' => (int) hexdec($crc32),
            'rand' => (int) hexdec($rand),
            'hash' => hex2bin($hash),
        ];

        return $crc32 === ($this->crc32() % 0x10000);
    }

    /**
     * add '-' at correct positions in the UUID.
     *
     * @param string $uuid
     * @param string $sep
     *
     * @return string
     */
    protected static function expand($uuid, $sep)
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
    protected static function collapse($uuid, $sep)
    {
        return strtr($uuid, $sep, null);
    }
}
