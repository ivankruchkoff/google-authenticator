=== Google Authenticator ===
Contributors: Henrik.Schack
Donate Link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=CA36JVKMLE9EA&lc=DK&item_number=Google%20Authenticator&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_LG%2egif%3aNonHosted
Tags: authentication,otp,password,security,login,android,iphone,blackberry
Requires at least: 3.1.2
Tested up to: 3.2
Stable tag: 0.35

Google Authenticator for your WordPress blog.

== Description ==

The Google Authenticator plugin for WordPress gives you two-factor authentication using the Google Authenticator app for Android/iPhone/Blackberry.

If you are security aware, you may already have the Google Authenticator app installed on your smartphone, using it for two-factor authentication on your Gmail or Google Apps account.

The two-factor authentication requirement can be enabled on a per-user basis. You could enable it for your administrator account, but log in as usual with less privileged accounts.

If You need to maintain your blog using an Android/iPhone app, or any other software using the XMLRPC interface, you can enable the App password feature in this plugin, 

but please note that enabling the App password feature will make your blog less secure.

== Installation ==

1. Install and activate the plugin.
2. Enter a description on the Users -> Profile and Personal options page, in the Google Authenticator section.
3. Scan the generated QR code with your phone, or enter the secret manually (remember to pick the time based one).
4. Remember to hit the **Update profile** button at the bottom of the page before leaving the Personal options page.
4. That's it, your WordPress blog is now a little more secure.

== Frequently Asked Questions ==

= Can I use Google Authenticator for WordPress with the Android/iPhone apps for WordPress? =

Yes, you can enable the App password feature to make that possible, but notice that the XMLRPC interface isn't protected by two-factor authentication, only a long password.

= I want to update the secret, should I just scan the new QR code after creating a new secret? =

No, you'll have to delete the existing account from the Google Authenticator app on your smartphone before you scan the new QR code, that is unless you change the description as well.

= Sometimes I am unable to log in using this plugin, the first code never works, what's wrong ? =

The Google Authenticator verification codes are time based, so it's crucial that the clock in your phone is accurate and in sync with the time on the server where your WordPress installation is hosted.

== Screenshots ==

1. The enhanced log-in box.
2. Google Authenticator section on the Profile and Personal options page.
3. QR code on the Profile and Personal options page.
4. Google Authenticator app on Android

== Changelog ==

= 0.35 =
* Initial WordPress app support added (XMLRPC).

= 0.30 =
* Code cleanup
* Changed generation of secret key, to no longer have requirement of SHA256 on the server
* German translation

= 0.20 =
* Initial release

== Credits ==

Thanks to:

[Tobias Bäthge](http://tobias.baethge.com/) for his code rewrite and German translation.

