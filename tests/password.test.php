<?php

use Leaf\Helpers\Password;

afterEach(fn () => Password::spice(''));

test('hash and verify round trip', function () {
    $hash = Password::hash('secret');

    expect($hash)->not->toBe('secret');
    expect(Password::verify('secret', $hash))->toBeTrue();
    expect(Password::verify('wrong', $hash))->toBeFalse();
});

test('bcrypt and argon2 helpers produce verifiable hashes', function () {
    $bcrypt = Password::bcrypt('secret');
    $argon = Password::argon2('secret');

    expect(str_starts_with($bcrypt, '$2y$'))->toBeTrue();
    expect(str_starts_with($argon, '$argon2id$'))->toBeTrue();
    expect(Password::bcryptVerify('secret', $bcrypt))->toBeTrue();
    expect(Password::argon2Verify('secret', $argon))->toBeTrue();
});

test('hash accepts algorithm options', function () {
    $hash = Password::hash('secret', Password::BCRYPT, ['cost' => 4]);

    expect(Password::verify('secret', $hash))->toBeTrue();
});

test('spice peppers every hash and verify via hmac', function () {
    Password::spice('pepper');

    $hash = Password::hash('secret');

    expect(Password::verify('secret', $hash))->toBeTrue();
    // the stored hash is of the hmac'd password, not a concatenation
    expect(password_verify(hash_hmac('sha256', 'secret', 'pepper'), $hash))->toBeTrue();
    // a verify without the spice must fail
    Password::spice('');
    expect(Password::verify('secret', $hash))->toBeFalse();
    // raw password_verify also fails without the pepper
    expect(password_verify('secret', $hash))->toBeFalse();
});

test('legacy concatenated-spice hashes still verify', function () {
    Password::spice('pepper');

    $legacyHash = password_hash('pepper' . 'secret', PASSWORD_DEFAULT);

    expect(Password::verify('secret', $legacyHash))->toBeTrue();
    expect(Password::verify('wrong', $legacyHash))->toBeFalse();
});

test('needsRehash flags legacy hashes so they migrate on login', function () {
    Password::spice('pepper');

    $legacyHash = password_hash('pepper' . 'secret', PASSWORD_DEFAULT);
    $modernHash = Password::hash('secret');

    expect(Password::needsRehash('secret', $legacyHash))->toBeTrue();
    expect(Password::needsRehash('secret', $modernHash))->toBeFalse();

    // migrating: re-hash while the plain password is in hand
    $migrated = Password::hash('secret');
    expect(Password::verify('secret', $migrated))->toBeTrue();
    expect(Password::needsRehash('secret', $migrated))->toBeFalse();
});

test('needsRehash also reflects algorithm changes', function () {
    $bcryptHash = Password::hash('secret', Password::BCRYPT, ['cost' => 4]);

    expect(Password::needsRehash('secret', $bcryptHash, Password::ARGON2))->toBeTrue();
});

test('spice can be read back and cleared', function () {
    Password::spice('pepper');
    expect(Password::spice())->toBe('pepper');

    Password::spice('');
    expect(Password::spice())->toBeNull();
});
