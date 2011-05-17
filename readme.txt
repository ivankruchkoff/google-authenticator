=== Google Authenticator ===
Contributors: Henrik.Schack
Donate Link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=CA36JVKMLE9EA&lc=DK&item_number=Google%20Authenticator&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_LG%2egif%3aNonHosted
Tags: authentication,otp,password,security,login,android,iphone,blackberry
Requires at least: 3.1.2
Tested up to: 3.1.2
Stable tag: 0.20

Google Authenticator for your Wordpress blog.

== Description ==

The Google Authenticator plugin for WordPress gives you multifactor authentication using the Google Authenticator app for Android/iPhone/Blackberry.

If you're security aware you may allready have the Google Authenticator app installed, using it for multifactor authentication on your Gmail or Google Apps account.

The multifactor authentication requirement can be enabled on a per user basis, You could enable it for your administrator account, but login as usual with less privileged accounts.


** Notice: This plugin requires the SHA1 & SHA256 hashing algorithms to be available in your PHP installation, it's not possible to activate the plugin without **

== Installation ==

1. Install and activate the plugin.
2. Enter a description on the Users -> Profile and Personal options page, in the Google Authenticator section.
3. Scan the generated QR code with your phone, or enter the secret manually (remember to pick the time based one)
4. Remember to hit the **Update profile** button at the bottom of the page before leaving the Personal options page.
4. That's it, your Wordpress blog is now a little more secure.

== Frequently Asked Questions ==

= Are there any special requirements for my Wordpress/PHP installation ? =

Yes, your PHP installation needs the SHA1 & SHA256 hashing algorithms.

= Can I use Google Authenticator for Wordpress with the Android/iPhone apps for Wordpress ? =

No, that wont work, but you could create a special account for mobile usage and choose not to enable 
the Google Authenticator this account.

= I want to update the secret, should I just scan the new QR code after creating a new secret ? =

No you'll have to delete the existing account from your Google Authenticator app before you scan the new QR code, that is unless you
change the description as well.

= Sometimes I am unable to login using this plugin, the first code never works, what's wrong ? =

The Google Authenticator verification codes are time based, so it's crucial the clock in your phone is accurate. 


== Screenshots ==

1. The enhanced loginbox.
2. Google Authenticator section on the Profile and Personal options page.
3. QR code on the Profile and Personal options page.
4. Google Authenticator app on Android

== Changelog ==

= 0.20 =
* Initial release
