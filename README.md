# Google Authenticator

Two-factor authentication for WordPress using Google Authenticator or any other time-based (TOTP) authenticator app.

| | |
|---|---|
| Contributors | ivankk |
| Tags | authentication, otp, password, security, login |
| Requires WordPress | 4.5 or later |
| Tested up to | WordPress 7.2 |
| Requires PHP | 7.2 or later (tested up to 8.6) |
| Stable version | 0.59 |
| License | [GPLv2 or later](https://www.gnu.org/licenses/gpl-2.0.html) |

Install it from [WordPress.org](https://wordpress.org/plugins/google-authenticator/).

## Description

Google Authenticator adds a second step to the WordPress login. After their password, users enter a 6-digit code from an authenticator app on their phone, so a stolen password alone is no longer enough to get in.

It works with Google Authenticator and any other app that supports time-based one-time passwords (TOTP), such as Microsoft Authenticator, Authy, 1Password, Bitwarden or KeePassXC.

**Features**

* **Per-user two-factor authentication.** Each user turns it on from their profile and scans a QR code with their app.
* **Mandatory 2FA by role.** Administrators can require it for chosen roles, such as Administrator and Editor. Users with any of those roles are sent to a setup page until they have enrolled. On multisite this can be set per site or for the whole network, and the network settings can also require it for all Super Admins.
* **Brute-force protection.** After 5 wrong codes sent with the correct password, further attempts are blocked for 1 minute, doubling with each further wrong code up to 1 hour.
* **Replay protection.** Each code can only be used once.
* **Two-screen sign-in (optional).** Ask for the code on a second screen after the username and password.
* **Relaxed mode** for phones whose clock drifts, accepting codes from up to 4 minutes either side.
* **App passwords** for XML-RPC clients that can't ask for a code.
* **Admin controls.** Administrators can turn two-factor authentication off for a user, or hide the settings from them.

Please note that turning on the App password feature lowers the security of that account: XML-RPC logins with an app password don't need a code, only the long app password.

## Installation

1. Make sure your server's clock is accurate (for example, that an NTP service is running). The codes are time based, so a wrong server clock means codes won't match.
2. Install and activate the plugin.
3. Go to **Users → Profile** and find the **Google Authenticator Settings** section.
4. Scan the QR code with your authenticator app, or type in the secret (choose "time based"). You may also want to write the secret down and keep it somewhere safe.
5. Tick **Active**, type the code your app shows into **Authenticator Code** and click **Update Profile**. Google Authenticator is only turned on if the code is right, so a mistake when adding the site to the app can't lock you out.
6. Optional: go to **Settings → Google Authenticator** to require two-factor authentication for certain roles or to turn on two-screen sign-in. On multisite, network-wide settings are under **Network Admin → Settings → Google Authenticator**.

## Frequently Asked Questions

### Which authenticator apps can I use?

Any app that supports time-based one-time passwords (TOTP), including Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden and KeePassXC. Several of these also run on a computer, so a smartphone isn't required.

### Can I use it with apps that log in over XML-RPC?

Yes. Enable the App password feature on your profile, click **Create new password**, and use that password in the app. Note that XML-RPC logins with an app password aren't protected by a verification code, only by the long app password.

### Does two-factor authentication apply to WordPress Application Passwords (REST API)?

No. WordPress's built-in Application Passwords (under **Users → Profile → Application Passwords**) are used by REST API clients and don't go through the login form, by WordPress's design. They can only be created by someone who is already logged in. If you don't use them, you can turn them off with the `wp_is_application_passwords_available` filter.

### I can't log in. What's wrong?

The codes are time based, so the clock on your phone must match the clock on your web server. Make sure your phone sets its date and time automatically, and that your server's clock is correct.

You can also enable **Relaxed mode** in your profile, which accepts codes from up to 4 minutes either side.

### I'm locked out. How do I get back in?

* Another administrator can untick **Active** in the Google Authenticator section of your user's edit page.
* With WP-CLI: `wp user meta update <your-username> googleauthenticator_enabled disabled`
* With SFTP or SSH access, rename or delete the `wp-content/plugins/google-authenticator` folder. You can then log in with your username and password, and put the plugin back afterwards.

### It says "Too many incorrect Google Authenticator codes". What now?

Wait for the time shown and try again. Blocks start at 1 minute and double with each further wrong code, up to 1 hour. A successful login resets the count.

Only wrong codes sent together with the correct password count. If you didn't cause the block yourself, someone else knows your password: change it.

### Can I create backup codes?

The plugin doesn't generate backup codes. Use an authenticator app that backs up or syncs your accounts (Google Authenticator can sync to your Google account, and Microsoft Authenticator, 1Password and Bitwarden have backups too), and keep a copy of your secret somewhere safe. An administrator can also turn two-factor authentication off for your account.

### I want to change my secret. Do I just scan the new QR code?

Click **Create new secret**, scan the new QR code, type the code your app shows for it into **Authenticator Code** and click **Update Profile**. The new secret is only saved if the code is right; after that you can delete the old entry from your app.

### Does it work with multiple users?

Yes. Each user has their own secret and settings.

### Are there hooks for developers?

* `google_authenticator_needs_setup` (filter): whether the current user must set up two-factor authentication.
* `google_authenticator_allowed_failed_codes` (filter): wrong codes allowed before attempts are blocked. Default 5.
* `google_authenticator_lockout_duration` (filter): length of a block in seconds. Default 60, doubling up to 3600.
* `google_authenticator_failed_code` (action): fires when a wrong code is sent with the correct password.
* `google_authenticator_code_reused` (action): fires when a code that was already used is sent again.
* `google_authenticator_default_description` (filter): the description suggested for a user's entry in their authenticator app. Default: the site name. For example, to tell several accounts on the same site apart: `add_filter( 'google_authenticator_default_description', function ( $description, $user ) { return $description . ' (' . $user->user_login . ')'; }, 10, 2 );`
* `google_authenticator_hide_settings` (filter): whether to hide the Google Authenticator settings from a user's profile page. Receives the user's "Hide settings from user" setting and the user ID, so you can hide them for whole roles or for everyone. The mandatory setup page is always shown.

Wrong codes also fire WordPress's standard `wp_login_failed` action, so login-limiting plugins see them.

### Any known incompatibilities?

Yes. The replay protection isn't compatible with the test/setup mode of the "Stop Spammer Registrations" plugin. Untick its "Check credentials on all login attempts" option before installing this plugin.

## Screenshots

1. The login form with the Google Authenticator code field.
2. The Google Authenticator section on the Profile page.
3. The QR code on the Profile page.
4. The Google Authenticator app on Android.
5. An example QR code to scan with your authenticator app.

## Changelog

### 0.59
* Turning on Google Authenticator from the profile page, or saving a new secret while it is on, now needs a code from your authenticator app, so a mistake when adding the site to the app can no longer lock you out. Administrators can still turn it on for other users without a code.
* On multisite, the network settings can now require 2FA for all Super Admins, including those with no role on a site.
* Codes copied from an authenticator app are now accepted with any separator between the digits, such as "012 345", "012-345" or the no-break and thin spaces some apps and phones insert. Previously any space made a valid code fail.
* New filters `google_authenticator_default_description` and `google_authenticator_hide_settings`, and "Hide settings from user" no longer hides the mandatory setup page.
* Fixed the spelling of the "Successfully saved" settings messages, so they are now translated too.
* Translations: the new strings are translated into all 24 languages. Like the rest, they are machine-assisted, so corrections from native speakers are welcome on translate.wordpress.org.

### 0.58
* Security: Wrong verification codes are now rate limited. After 5 wrong codes sent with the correct password, further attempts are blocked for 1 minute, doubling up to 1 hour. Previously the 6 digit code could be brute-forced by anyone who knew the password.
* Security: The verification code is only checked once the password is correct, and a wrong password and a wrong code now return the same error.
* Security: The 2FA secret shown on the setup and profile pages can no longer be set from a link (secret fixation).
* Security: Mandatory 2FA now applies when any of a user's roles requires it, not only their first role.
* Security: The setup page can no longer replace the secret of an account that already has 2FA enabled.
* Security: Errors from other login checks (lockout or captcha plugins) are no longer overridden by App password logins.
* Hardening: Stricter validation of verification codes and secrets, input unslashing and output escaping throughout.
* Fixed two screen sign-in for passwords containing quotes or backslashes.
* Fixed site settings on multisite being editable only when network-wide settings were enforced (the reverse of what was intended).
* Fixed the network settings page on WordPress 4.5.
* Login form: the code field now lines up with the username and password fields in every browser. It uses the same markup as WordPress's own fields; it was slightly narrower in some browsers, such as Safari.
* Login form: the "leave this field empty" hint is now a help button next to the label (WordPress 7.1 and later), so it can be read on phones and by screen readers.
* Login form: Safari and password managers can fill in the code automatically, and phones show a number keypad.
* Login form: the cursor now starts in the username field, as on a normal WordPress login, instead of jumping to the code field. On the two-screen sign-in page it still starts in the code field.
* Login form: a wrong code shakes the form, like a wrong password does.
* Codes typed with full-width digits (for example with a Japanese input method) are now accepted in every browser.
* Fixed the QR code for descriptions or site names with non-English characters. They were encoded incorrectly, so authenticator apps could show a garbled name or reject the code.
* Fixed the setup page not sending users who already have two-factor authentication enabled back to the dashboard.
* Updated the list of authenticator apps on the setup page (Google Authenticator, Microsoft Authenticator and Authy) and removed discontinued ones.
* Removed a stray space at the end of newly generated app passwords.
* New action `google_authenticator_code_reused`. The "Man-in-the-middle attack detected" message is now only written to the PHP error log when WP_DEBUG is on.
* Code cleanup for the WordPress coding standards and Plugin Check: safe redirects, translator comments and text domains, current jQuery methods (no more jQuery Migrate warnings), and removal of obsolete code.
* Updated the translation template.
* Translations: added Arabic, Chinese (Taiwan), Czech, Hungarian, Indonesian, Japanese, Korean, Persian, Portuguese (Portugal), Russian, Spanish (Mexico), Turkish, Ukrainian and Vietnamese, and completed and corrected the existing ten languages. All 24 now cover every string. The new and corrected strings are machine-assisted, so corrections from native speakers are very welcome on translate.wordpress.org.
* Tested with WordPress 7.2 and PHP 7.2 to 8.6.
* Updated readme and FAQ.

### 0.57
* Security: Fixed an authentication bypass where an empty app password could be accepted over XML-RPC (CVE-2026-88759). Thanks to Kuba (Wordfence).
* Saving the profile no longer stores an app password unless one has actually been generated.
* Empty or legacy (pre-2014 sha1) app passwords are now always rejected and removed. Affected users should create a new app password from their profile.

### 0.56
* Fixed CSRF account lockout bug.

### 0.55
* Improved PHP compatibility for PHP 7.4 through 8.5.
* Fixed deprecated and strict runtime issues in plugin code.
* Improved compatibility and safety of Base32 handling.

### 0.54
* Fixed a bug in multisite.

### 0.53
* Add a Polish translation

### 0.52
* Add a Dutch translation
* Add a Portuguese translation

### 0.51
* Fix a regression that broke app passwords

### 0.50
* New maintainer ivankk
* Conditionally include base32 class

### 0.49
* More streamlined sign-up flow for users, configuration screen for admins.
* Multisite support to either enable 2fa by role on a site, and/or on a network.
* Added filter google_authenticator_needs_setup to determine if user needs to enable 2fa.
* Added two part login process that can ask for 2fa code on a second login screen.
* Fixed a security bug that continued check_otp even if authenticate had already returned an error.

### 0.48
* Security fix / compatability with WordPress 4.5

### 0.47
* Google chart API replaced with jquery-qrcode
* QR codes now contain a heading saying WordPress (Feature request by Flemming Mahler)
* Danish translation & updated .pot file.
* Plugin now logs login attempts recognized as Man-in-the-middle attacks.

### 0.46
* Man-in-the-middle attack protection added.
* Show warning before displaying the QR code.
* FAQ updated.

### 0.45
* Spaces in the description field should now work on iPhones.
* Some depricated function calls replaced.
* Code inputfield easier to use for .jp users now.
* Sanitize description field input.
* App password hash function switched to one that doesn't have rainbow tables available.
* PHP notices occurring during app password login removed.

### 0.44
* Installation/FAQ section updated.
* Simplified Chinese translation by Kaijia Feng added.
* Tabindex on loginpage removed, no longer needed, was used by older WordPress installations.
* Inputfield renamed to "googleotp".
* Defaultdescription changed to "WordPressBlog" to avoid trouble for iPhone users.
* Compatibility with Ryan Hellyer's plugin http://geek.ryanhellyer.net/products/deactivate-google-authenticator/
* Must enter all 6 code digits.

### 0.43
* It's now possible for an admin to hide the Google Authenticaator settings on a per-user basis. (Feature request by : Skate-O)

### 0.42
* Autocomplete disabled on code input field. (Feature request by : hiphopsmurf)

### 0.41
* Italian translation by Aldo Latino added.

### 0.40
* Bugfix, typo corrected and PHP notices removed. Thanks to Dion Hulse for his patch.

### 0.39
* Bugfix, Description was not saved to WordPress database when updating profile. Thanks to xxdesmus for noticing this.

### 0.38
* Usability fix, input field for codes changed from password to text type.

### 0.37
* The plugin now supports "relaxed mode" when authenticating. If selected, codes from 4 minutes before and 4 minutes after will work. 30 seconds before and after is still the default setting.

### 0.36
* Bugfix, now an App password can only be used for XMLRPC/APP-Request logins.

### 0.35
* Initial WordPress app support added (XMLRPC).

### 0.30
* Code cleanup
* Changed generation of secret key, to no longer have requirement of SHA256 on the server
* German translation

### 0.20
* Initial release

## Upgrade Notice

### 0.58
Security release: adds brute-force protection for verification codes and fixes several other security issues. Please update.

### 0.57
Security release: fixes an XML-RPC authentication bypass (CVE-2026-88759). Please update.

## Credits

Thanks to:

[Kuba](https://www.wordfence.com/) (Wordfence) for responsibly disclosing an XML-RPC app password authentication bypass.

[Miguel Mendez Z](https://wpscan.com/) for responsibly disclosing a CSRF account lockout vulnerability.

[Oleksiy](https://profiles.wordpress.org/evinak/) for a bugfix in multisite.

[Paweł Nowacki](https://github.com/pancek) for the Polish translation

[Fabio Zumbi](https://github.com/FabioZumbi12) for the Portuguese translation

[Guido Schalkx](https://www.guidoschalkx.com/) for the Dutch translation.

[Henrik.Schack](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=henrik%40schack%2edk&lc=US&item_name=Google%20Authenticator&item_number=Google%20Authenticator&no_shipping=0&no_note=1&tax=0&bn=PP%2dDonationsBF&charset=UTF%2d8) for writing/maintaining versions 0.20 through 0.48

[Tobias Bäthge](http://tobias.baethge.com/) for his code rewrite and German translation.

[Pascal de Bruijn](http://blog.pcode.nl/) for his "relaxed mode" idea.

[Daniel Werl](http://technobabbl.es/) for his usability tips.

[Dion Hulse](http://dd32.id.au/) for his bugfixes.

[Aldo Latino](http://profiles.wordpress.org/users/aldolat/) for his Italian translation.

[Kaijia Feng](http://www.kaijia.me/) for his Simplified Chinese translation.

[Alex Concha](http://www.buayacorp.com/) for his security tips.

[Jerome Etienne](http://jetienne.com/) for his jquery-qrcode plugin.

[Sébastien Prunier](http://orizhial.com/) for his Spanish and French translation.
