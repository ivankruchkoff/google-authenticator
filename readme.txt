=== Google Authenticator ===
Contributors: Henrik.Schack
Donate Link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=henrik%40schack%2edk&lc=US&item_name=Google%20Authenticator&item_number=Google%20Authenticator&no_shipping=0&no_note=1&tax=0&bn=PP%2dDonationsBF&charset=UTF%2d8
Tags: authentication,otp,password,security,login,android,iphone,blackberry
Requires at least: 3.1.2
Tested up to: 3.3
Stable tag: 0.39

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

= The iPhone app keeps telling me I'm trying to scan an authentication token barcode that isn't valid, what to do ? =

Apparently the iPhone app won't accept a barcode containing space characters in the description, removing space characters in the description should fix the problem.

= Can I use Google Authenticator for WordPress with the Android/iPhone apps for WordPress? =

Yes, you can enable the App password feature to make that possible, but notice that the XMLRPC interface isn't protected by two-factor authentication, only a long password.

= I want to update the secret, should I just scan the new QR code after creating a new secret? =

No, you'll have to delete the existing account from the Google Authenticator app on your smartphone before you scan the new QR code, that is unless you change the description as well.

= I am unable to log in using this plugin, what's wrong ? =

The Google Authenticator verification codes are time based, so it's crucial that the clock in your phone is accurate and in sync with the clock on the server where your WordPress installation is hosted. 

If you have an Android phone, you can use an app like [ClockSync](https://market.android.com/details?id=ru.org.amip.ClockSync) to set your clock in case your Cell provider doesn't provide accurate time information

Another option is to enable "relaxed mode" in the settings for the plugin, this will enable more valid codes by allowing up to a 4 min. timedrift in each direction.

== Screenshots ==

1. The enhanced log-in box.
2. Google Authenticator section on the Profile and Personal options page.
3. QR code on the Profile and Personal options page.
4. Google Authenticator app on Android

== Changelog ==

= 0.39 =
* Bugfix, Description was not saved to WordPress database when updating profile. Thanks to xxdesmus for noticing this.

= 0.38 =
* Usability fix, input field for codes changed from password to text type.

= 0.37 =
* The plugin now supports "relaxed mode" when authenticating. If selected, codes from 4 minutes before and 4 minutes after will work. 30 seconds before and after is still the default setting.

= 0.36 =
* Bugfix, now an App password can only be used for XMLRPC/APP-Request logins.

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

[Pascal de Bruijn](http://blog.pcode.nl/) for his "relaxed mode" idea.

[Daniel Werl](http://technobabbl.es/) for his usability tips.


