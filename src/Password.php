<?php

namespace Leaf\Helpers;

/**
 * Leaf Password Helper
 * ---------------------------------------------
 * Work easier and faster with passwords
 *
 * @author Michael Darko <mychi.darko@gmail.com>
 * @since 2.0.0
 */
class Password
{
    public const BCRYPT = PASSWORD_BCRYPT;
    public const ARGON2 = PASSWORD_ARGON2ID;
    public const DEFAULT = PASSWORD_DEFAULT;

    /**Spice up an inputted password for better security */
    protected static $spice = null;

    /**
     * Get or set password 'spice' (a pepper appended to every password).
     * Pass null to read the current spice, an empty string to clear it.
     */
    public static function spice($spice = null)
    {
        if ($spice === null) {
            return static::$spice;
        }

        static::$spice = $spice ?: null;
    }

    /**
     * Apply the spice to a password before hashing/verifying.
     *
     * The password is keyed through HMAC-SHA256 with the spice as the
     * secret, which is the standard way to pepper a password — unlike
     * concatenation, the pepper never sits directly next to attacker
     * controlled input, and the result is a fixed-length string, so
     * bcrypt's 72-byte truncation can't silently eat it.
     */
    protected static function season(string $password): string
    {
        if (!static::$spice) {
            return $password;
        }

        return hash_hmac('sha256', $password, static::$spice);
    }

    /**
     * Create a password hash
     *
     * See the [password algorithm constants](https://secure.php.net/manual/en/password.constants.php) for documentation on the supported options for each algorithm.
     */
    public static function hash(string $password, $algorithm = self::DEFAULT, array $options = [])
    {
        return password_hash(static::season($password), $algorithm, $options);
    }

    /**
     * Checks if the given hash matches the given options.
     *
     * Hashes created by older versions of this module (which concatenated
     * the spice instead of HMAC-ing it) are still verified, so enabling
     * the new scheme never locks existing users out. Use needsRehash()
     * after a successful login to migrate old hashes forward.
     */
    public static function verify(string $password, $hashedPassword): bool
    {
        if (password_verify(static::season($password), $hashedPassword)) {
            return true;
        }

        // legacy fallback: pre-v5 spice was concatenated
        return static::$spice && password_verify(static::$spice . $password, $hashedPassword);
    }

    /**
     * Check whether a hash should be re-created — because the algorithm
     * or options changed, or because it still uses the legacy concatenated
     * spice. Call after a successful verify(), while the plain password is
     * available, and store a fresh hash() when it returns true.
     */
    public static function needsRehash(string $password, string $hashedPassword, $algorithm = self::DEFAULT, array $options = []): bool
    {
        if (password_needs_rehash($hashedPassword, $algorithm, $options)) {
            return true;
        }

        // verified through the legacy concat fallback, not the hmac scheme
        return static::$spice
            && !password_verify(static::season($password), $hashedPassword)
            && password_verify(static::$spice . $password, $hashedPassword);
    }

    /**
     * Generate an Argon2 hashed password
     *
     * @param string $password The user's password to hash
     * @param array $options Options for Argon hash
     *
     * Supported Options:
     * - memory_cost (integer) - Maximum memory (in bytes) that may be used to compute the Argon2 hash. Defaults to PASSWORD_ARGON2_DEFAULT_MEMORY_COST.
     * - time_cost (integer) - Maximum amount of time it may take to compute the Argon2 hash. Defaults to PASSWORD_ARGON2_DEFAULT_TIME_COST.
     * - threads (integer) - Number of threads to use for computing the Argon2 hash. Defaults to PASSWORD_ARGON2_DEFAULT_THREADS.
     *
     * Available as of PHP 7.2.0.
     */
    public static function argon2(string $password, array $options = [])
    {
        return password_hash(static::season($password), self::ARGON2, $options);
    }

    /**
     * Checks if the given argon2 hash matches the given options.
     */
    public static function argon2Verify(string $password, string $hashedPassword): bool
    {
        return static::verify($password, $hashedPassword);
    }

    /**
     * Generate an Argon2 hashed password
     *
     * @param string $password The user's password to hash
     * @param array $options Options for Argon hash
     */
    public static function bcrypt(string $password, array $options = [])
    {
        return password_hash(static::season($password), self::BCRYPT, $options);
    }

    /**
     * Checks if the given BCRYPT hash matches the given options.
     */
    public static function bcryptVerify(string $password, string $hashedPassword): bool
    {
        return static::verify($password, $hashedPassword);
    }
}
