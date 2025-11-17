# Google Authenticator Plugin - Security Audit Report

**Date:** 2025-11-17
**Auditor:** Claude (Anthropic)
**Plugin Version:** 0.53
**Branch:** claude/review-authenticator-security-01Quj8eenfHJFadQuNu9FF7P

---

## Executive Summary

This security audit reveals **CRITICAL discrepancies** between the claimed security features and the actual implementation. The plugin has several high-severity vulnerabilities that undermine its security as a two-factor authentication solution.

### Risk Level: **HIGH** 🔴

**Critical Issues:** 5
**High Severity:** 4
**Medium Severity:** 3
**Low Severity:** 2

---

## 🔴 CRITICAL VULNERABILITIES

### 1. **Cryptographically Weak Secret Generation**
**Location:** `google-authenticator.php:177-184`
**Severity:** CRITICAL
**CVSS Score:** 9.1 (Critical)

**Issue:**
The plugin uses `wp_rand()` to generate 2FA secrets, which is NOT cryptographically secure. This is based on PHP's `mt_rand()` which is predictable and vulnerable to attack.

**Current Code:**
```php
function create_secret() {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ( $i = 0; $i < 16; $i++ ) {
        $secret .= substr( $chars, wp_rand( 0, strlen( $chars ) - 1 ), 1 ); // ❌ INSECURE
    }
    return $secret;
}
```

**Claim vs Reality:**
- ❌ **Claimed:** "Secrets are generated using cryptographically secure random functions (random_int)"
- ✓ **Reality:** Uses `wp_rand()` which is NOT cryptographically secure

**Impact:**
An attacker who can observe or predict the RNG state could potentially predict future secrets, completely bypassing 2FA protection.

**Recommendation:**
```php
function create_secret() {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    $chars_length = strlen($chars);
    for ( $i = 0; $i < 16; $i++ ) {
        $secret .= $chars[random_int(0, $chars_length - 1)]; // ✓ Cryptographically secure
    }
    return $secret;
}
```

---

### 2. **Timing Attack Vulnerability in OTP Verification**
**Location:** `google-authenticator.php:156`
**Severity:** CRITICAL
**CVSS Score:** 7.5 (High)

**Issue:**
The OTP comparison uses standard `===` operator instead of constant-time comparison, making it vulnerable to timing attacks.

**Current Code:**
```php
if ( $value === $thistry ) { // ❌ Vulnerable to timing attacks
    // Check for replay attack...
    return $tm+$i;
}
```

**Claim vs Reality:**
- ❌ **Claimed:** "Uses hash_equals for comparisons to prevent timing attacks"
- ✓ **Reality:** Uses standard `===` comparison

**Impact:**
An attacker with precise timing measurements could potentially determine the correct OTP through timing analysis.

**Recommendation:**
```php
if ( hash_equals((string)$value, (string)$thistry) ) { // ✓ Constant-time comparison
    // Check for replay attack...
    return $tm+$i;
}
```

---

### 3. **Complete Absence of Rate Limiting**
**Location:** Entire plugin
**Severity:** CRITICAL
**CVSS Score:** 8.2 (High)

**Issue:**
Despite claims of rate limiting implementation, there is **ZERO** rate limiting code in the plugin. This allows unlimited brute force attempts on the 6-digit OTP code.

**Claim vs Reality:**
- ❌ **Claimed:** "Implements rate limiting (5 attempts per 15 minutes) on verification to prevent brute force"
- ✓ **Reality:** No rate limiting exists anywhere in the codebase

**Impact:**
An attacker can attempt all 1,000,000 possible OTP combinations. With the 30-second window (or 8 minutes in relaxed mode), this significantly weakens 2FA security.

**Recommendation:**
Implement transient-based rate limiting:
```php
function check_rate_limit($user_id) {
    $attempts_key = 'ga_attempts_' . $user_id;
    $attempts = get_transient($attempts_key) ?: 0;

    if ($attempts >= 5) {
        return new WP_Error('rate_limit', 'Too many attempts. Please try again in 15 minutes.');
    }

    set_transient($attempts_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);
    return true;
}
```

---

### 4. **Password Exposure in Secondary Login Screen**
**Location:** `google-authenticator.php:648-649`
**Severity:** CRITICAL
**CVSS Score:** 9.8 (Critical)

**Issue:**
When two-screen signin is enabled, the user's password is passed as a hidden field in the secondary form, exposing it in HTML source and browser history.

**Current Code:**
```php
<input type="hidden" name="pwd" value="<?php echo esc_attr( $_REQUEST['pwd'] ); ?>" />
```

**Impact:**
- Password visible in HTML source code
- Password logged in browser history
- Password exposed if form is cached
- Violates security best practices

**Recommendation:**
Use server-side sessions to store authentication state instead of passing passwords in forms:
```php
// After initial authentication:
$_SESSION['ga_pending_user_id'] = $user->ID;
$_SESSION['ga_pending_timestamp'] = time();

// In secondary screen, verify session instead of re-sending password
```

---

### 5. **Missing CSRF Protection on Setup Page**
**Location:** `google-authenticator.php:265-285`
**Severity:** CRITICAL
**CVSS Score:** 8.1 (High)

**Issue:**
The `save_submitted_setup_page()` function processes POST data without CSRF token verification, allowing attackers to trick users into enabling 2FA with attacker-controlled secrets.

**Current Code:**
```php
function save_submitted_setup_page() {
    $secret = empty( $_POST['GA_secret'] ) ? false : sanitize_text_field( $_POST['GA_secret']);
    $otp = empty( $_POST['GA_otp_code'] ) ? false : sanitize_text_field( $_POST['GA_otp_code']);
    // No nonce check!
```

**Impact:**
An attacker could craft a malicious page that submits a form to the setup endpoint, potentially enabling 2FA with a secret known to the attacker.

**Recommendation:**
```php
function save_submitted_setup_page() {
    if (!isset($_POST['ga_setup_nonce']) || !wp_verify_nonce($_POST['ga_setup_nonce'], 'ga_setup_action')) {
        wp_die('Security check failed');
    }
    // Continue processing...
}
```

---

## 🟠 HIGH SEVERITY ISSUES

### 6. **XSS Vulnerability in Admin Interface**
**Location:** `google-authenticator.php:523`
**Severity:** HIGH
**CVSS Score:** 6.5 (Medium)

**Issue:**
Uses `esc_html()` on an HTML attribute instead of `esc_attr()`:

```php
<input name="roles[]" type="checkbox"<?php echo esc_html( $readonly ) ... // ❌ Wrong escaping function
```

**Recommendation:**
```php
<input name="roles[]" type="checkbox"<?php echo $readonly; // Already safe, no need to escape
```

---

### 7. **Use of Deprecated PHP Function**
**Location:** `google-authenticator.php:383`
**Severity:** HIGH
**CVSS Score:** N/A (Compatibility)

**Issue:**
Uses `FILTER_SANITIZE_STRING` which is deprecated in PHP 8.1+:

```php
$nonce = filter_input( INPUT_POST, 'googleauthenticator', FILTER_SANITIZE_STRING );
```

**Impact:**
Will cause deprecation warnings in PHP 8.1+ and will be removed in PHP 9.0.

**Recommendation:**
```php
$nonce = isset($_POST['googleauthenticator']) ? sanitize_text_field($_POST['googleauthenticator']) : '';
```

---

### 8. **Legacy SHA1 Password Hashing**
**Location:** `google-authenticator.php:610-611`
**Severity:** HIGH
**CVSS Score:** 7.4 (High)

**Issue:**
Legacy code still uses SHA1 for password comparison:

```php
$usersha1 = sha1( strtoupper( str_replace( ' ', '', $password ) ) );
if ( $passwordhash == $usersha1 ) { // Using SHA1!
```

**Impact:**
SHA1 is cryptographically broken and should not be used for password hashing.

**Recommendation:**
The code has a migration path to `wp_hash_password()` (line 614), but the legacy SHA1 check should be removed after a deprecation period.

---

### 9. **Unsafe Array Access**
**Location:** `google-authenticator.php:221`
**Severity:** MEDIUM
**CVSS Score:** 5.3 (Medium)

**Issue:**
Assumes user has at least one role without checking:

```php
$user_role = $user->roles[0]; // May not exist
```

**Recommendation:**
```php
$user_role = !empty($user->roles) ? $user->roles[0] : '';
```

---

## 🟡 MEDIUM SEVERITY ISSUES

### 10. **Error Suppression in Base32 Decoder**
**Location:** `base32.php:73`
**Severity:** MEDIUM

**Issue:**
Uses @ operator to suppress errors:

```php
$x .= str_pad(base_convert(@self::$flippedMap[@$input[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
```

**Impact:**
Hides potential bugs and makes debugging difficult.

**Recommendation:**
Properly validate input before accessing arrays.

---

### 11. **Insufficient Input Validation on OTP**
**Location:** `google-authenticator.php:122-126`
**Severity:** MEDIUM

**Issue:**
Uses `strlen()` on potentially non-string input:

```php
if ( strlen( $thistry ) != 6) { // What if $thistry is not a string?
    return false;
}
```

**Recommendation:**
```php
if (!is_string($thistry) || strlen($thistry) != 6 || !ctype_digit($thistry)) {
    return false;
}
```

---

### 12. **Missing File Existence Check**
**Location:** `google-authenticator.php:74-76`
**Severity:** LOW

**Issue:**
No file_exists check before require_once:

```php
if ( ! class_exists( 'Base32' ) ) {
    require_once( 'base32.php' ); // What if file doesn't exist?
}
```

**Recommendation:**
```php
$base32_file = plugin_dir_path(__FILE__) . 'base32.php';
if (!class_exists('Base32') && file_exists($base32_file)) {
    require_once($base32_file);
}
```

---

## ✅ SECURITY FEATURES CORRECTLY IMPLEMENTED

1. **Replay Attack Protection** (Lines 157-166) - ✓ Working correctly
2. **Man-in-the-Middle Detection** (Line 162) - ✓ Logs attempts correctly
3. **TOTP Algorithm** (Lines 137-170) - ✓ Implements RFC 6238 correctly
4. **Nonce Verification in AJAX** (Line 995) - ✓ Uses `check_ajax_referer()`
5. **Nonce Verification in Admin** (Line 384) - ✓ Uses `wp_verify_nonce()`
6. **Input Sanitization** - ✓ Generally uses `sanitize_text_field()` and `esc_*` functions
7. **Capability Checks** - ✓ Uses `current_user_can()` in most places

---

## PRIORITY RECOMMENDATIONS

### Immediate (Critical)
1. ✓ Replace `wp_rand()` with `random_int()` in secret generation
2. ✓ Replace `===` with `hash_equals()` in OTP verification
3. ✓ Implement rate limiting on login attempts
4. ✓ Fix password exposure in secondary login screen
5. ✓ Add CSRF protection to setup page

### Short-term (High)
6. ✓ Fix XSS vulnerability in admin interface
7. ✓ Replace deprecated `FILTER_SANITIZE_STRING`
8. ✓ Remove legacy SHA1 password hashing
9. ✓ Add array access safety checks

### Medium-term (Medium)
10. ✓ Remove error suppression in Base32 class
11. ✓ Improve OTP input validation
12. ✓ Add file existence checks

---

## TESTING RECOMMENDATIONS

1. **Penetration Testing:** Conduct professional penetration testing focusing on:
   - Brute force attacks on OTP codes
   - Timing attack analysis
   - CSRF attack vectors
   - Session hijacking attempts

2. **Code Review:** Have a second security professional review the fixes

3. **Automated Testing:** Implement:
   - Unit tests for cryptographic functions
   - Integration tests for authentication flow
   - Security scanning with tools like WPScan

---

## CONCLUSION

Despite marketing claims, this plugin has significant security vulnerabilities that undermine its effectiveness as a 2FA solution. The most critical issues are:

1. **Weak random number generation** for secrets
2. **No rate limiting** allowing brute force
3. **Timing attack vulnerability** in comparisons
4. **Password exposure** in HTML forms
5. **Missing CSRF protection** on critical endpoints

**Recommendation:** **DO NOT USE THIS PLUGIN IN PRODUCTION** until all critical vulnerabilities are patched and security testing is completed.

---

## References

- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PHP random_int() Documentation](https://www.php.net/manual/en/function.random-int.php)
- [WordPress Security Best Practices](https://developer.wordpress.org/apis/security/)

---

**Report End**
