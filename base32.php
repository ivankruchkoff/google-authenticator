<?php

/**
 * Encode in Base32 based on RFC 4648.
 * Requires 20% more space than base64
 * Great for case-insensitive filesystems like Windows and URLs
 * (except for = char which can be excluded using the pad option for URLs).
 *
 * @package default
 * @author Bryan Ruiz
 **/
class Base32 {

    private static $map = array(
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        '='  // padding char
    );

    private static $flippedMap = array(
        'A' => 0,  'B' => 1,  'C' => 2,  'D' => 3,  'E' => 4,  'F' => 5,  'G' => 6,  'H' => 7,
        'I' => 8,  'J' => 9,  'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
        'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
        'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31
    );

    /**
     * Use padding false when encoding for URLs.
     *
     * @return string
     */
    public static function encode($input, $padding = true) {
        if ($input === '' || $input === null) {
            return '';
        }

        $input = (string) $input;
        $inputLength = strlen($input);
        $binaryString = '';

        for ($i = 0; $i < $inputLength; $i++) {
            $binaryString .= str_pad(base_convert((string) ord($input[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }

        $fiveBitBinaryArray = str_split($binaryString, 5);
        $base32 = '';
        $chunkCount = count($fiveBitBinaryArray);

        for ($i = 0; $i < $chunkCount; $i++) {
            $base32 .= self::$map[(int) base_convert(str_pad($fiveBitBinaryArray[$i], 5, '0'), 2, 10)];
        }

        if ($padding) {
            $x = strlen($binaryString) % 40;
            if ($x !== 0) {
                if ($x === 8) {
                    $base32 .= str_repeat(self::$map[32], 6);
                } elseif ($x === 16) {
                    $base32 .= str_repeat(self::$map[32], 4);
                } elseif ($x === 24) {
                    $base32 .= str_repeat(self::$map[32], 3);
                } elseif ($x === 32) {
                    $base32 .= self::$map[32];
                }
            }
        }

        return $base32;
    }

    public static function decode($input) {
        if ($input === '' || $input === null) {
            return '';
        }

        $input = strtoupper((string) $input);
        $paddingCharCount = substr_count($input, self::$map[32]);
        $allowedValues = array(6, 4, 3, 1, 0);

        if (!in_array($paddingCharCount, $allowedValues, true)) {
            return false;
        }

        for ($i = 0; $i < 4; $i++) {
            if (
                $paddingCharCount === $allowedValues[$i] &&
                substr($input, -$allowedValues[$i]) !== str_repeat(self::$map[32], $allowedValues[$i])
            ) {
                return false;
            }
        }

        $input = str_replace('=', '', $input);
        $input = str_split($input);
        $binaryString = '';
        $inputCount = count($input);

        for ($i = 0; $i < $inputCount; $i++) {
            if (!isset(self::$flippedMap[$input[$i]])) {
                return false;
            }
            $binaryString .= str_pad(base_convert((string) self::$flippedMap[$input[$i]], 10, 2), 5, '0', STR_PAD_LEFT);
        }

        $eightBits = str_split($binaryString, 8);
        $output = '';
        $eightBitCount = count($eightBits);

        for ($z = 0; $z < $eightBitCount; $z++) {
            if (strlen($eightBits[$z]) !== 8) {
                continue;
            }
            $output .= chr((int) base_convert($eightBits[$z], 2, 10));
        }

        return $output;
    }
}
