<?php
/*
Plugin Name: Google Authenticator
Plugin URI: http://henrik.schack.dk/google-authenticator-for-wordpress
Description: Two-Factor Authentication for WordPress using the Android/iPhone/Blackberry app as One Time Password generator.
Author: Henrik Schack
Version: 0.30
Author URI: http://henrik.schack.dk/
Compatibility: WordPress 3.2-RC2
Text Domain: google-authenticator
Domain Path: /lang

----------------------------------------------------------------------------

	Thanks to Bryan Ruiz for his Base32 encode/decode class, found at php.net.
	Thanks to Tobias Bäthge for his major code rewrite and German translation.
	
----------------------------------------------------------------------------

    Copyright 2011  Henrik Schack  (email : henrik@schack.dk)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

class GoogleAuthenticator {

static $instance; // to store a reference to the plugin, allows other plugins to remove actions

/**
 * Constructor, entry point of the plugin
 */
function __construct() {
    self::$instance = $this;
    add_action( 'init', array( $this, 'init' ) );
}

/**
 * Initialization, Hooks, and localization
 */
function init() {
    require_once( 'base32.php' );
    
    add_action( 'login_form', array( $this, 'loginform' ) );
    add_filter( 'wp_authenticate_user', array( $this, 'check_otp' ) );

    if ( defined( 'DOING_AJAX' ) && DOING_AJAX )
        add_action( 'wp_ajax_GoogleAuthenticator_action', array( $this, 'ajax_callback' ) );

    add_action( 'personal_options_update', array( $this, 'personal_options_update' ) );
    add_action( 'profile_personal_options', array( $this, 'profile_personal_options' ) );
    add_action( 'edit_user_profile', array( $this, 'edit_user_profile' ) );
    add_action( 'edit_user_profile_update', array( $this, 'edit_user_profile_update' ) );

    load_plugin_textdomain( 'google-authenticator', false, basename( dirname( __FILE__ ) ) . '/lang' );
}

/**
 * Check the verification code entered by the user.
 */
function verify( $secretkey, $thistry ) {
	
	$tm = floor( time() / 30 );
	
	$secretkey=Base32::decode($secretkey);
	// Keys from 30 seconds before and after are valid aswell.
	for ($i=-1; $i<2; $i++) {
		// Pack time into binary string
		$time=chr(0).chr(0).chr(0).chr(0).pack('N*',$tm+$i);
		// Hash it with users secret key
		$hm = hash_hmac( 'SHA1', $time, $secretkey, true );
		// Use last nipple of result as index/offset
		$offset = ord(substr($hm,-1)) & 0x0F;
		// grab 4 bytes of the result
		$hashpart=substr($hm,$offset,4);
		// Unpak binary value
		$value=unpack("N",$hashpart);
		$value=$value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;
		$value = $value % 1000000;
		if ( $value == $thistry ) {
			return true;
		}	
	}
	return false;
}

/**
 * Create a new random secret for the Google Authenticator app.
 * 16 characters, randomly chosen from the allowed Base32 characters
 * equals 10 bytes = 80 bits, as 256^10 = 32^16 = 2^80
 */ 
function create_secret() {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // allowed characters in Base32
    $secret = '';
    for ( $i = 0; $i < 16; $i++ ) {
        $secret .= substr( $chars, wp_rand( 0, strlen( $chars ) - 1 ), 1 );
    }
    return $secret;
}


/**
 * Add verification code field to login form.
 */
function loginform() {
    echo "\t<p>\n";
    echo "\t\t<label><a href=\"http://code.google.com/p/google-authenticator/\" target=\"_blank\" title=\"".__('If you don\'t have Google Authenticator enabled for your WordPress account, leave this field empty.','google-authenticator')."\">".__('Google Authenticator code','google-authenticator')."</a><span id=\"google-auth-info\"></span><br />\n";
    echo "\t\t<input type=\"password\" name=\"otp\" id=\"user_email\" class=\"input\" value=\"\" size=\"20\" tabindex=\"25\" /></label>\n";
    echo "\t</p>\n";
}


/**
 * Login form handling.
 * Check Google Authenticator verification code, if user has been setup to do so.
 * @param wordpressuser
 * @return user/loginstatus
 */
function check_otp( $user ) {

	// Does the user have the Google Authenticator enabled ?
	if ( trim(get_user_option('googleauthenticator_enabled',$user->ID)) == 'enabled' ) {

		// Get the users secret
		$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user->ID ) );
		
		// Get the verification code entered by the user trying to login
		$otp = intval( trim( $_POST[ 'otp' ] ) );
		
		// Valid code ?
		if ( ! $this->verify( $GA_secret, $otp ) )
			return new WP_Error( 'invalid_google_authenticator_token', __( '<strong>ERROR</strong>: The Google Authenticator code is incorrect or has expired.', 'google-authenticator' ) );
	}	
	return $user;
}


/**
 * Extend personal profile page with Google Authenticator settings.
 */
function profile_personal_options() {
	global $user_id, $is_profile_page;
	
	$GA_secret			=trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
	$GA_enabled			=trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	$GA_description		=trim( get_user_option( 'googleauthenticator_description', $user_id ) );

	// In case the user has no secret ready (new install), we create one.
	if ( '' == $GA_secret )
		$GA_secret = $this->create_secret();

	// Use "WordPress Blog" as default description
	if ( '' == $GA_description )
		$GA_description = __( 'WordPress Blog', 'google-authenticator' );

	echo "<h3>".__( 'Google Authenticator Settings', 'google-authenticator' )."</h3>\n";

	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";
	echo "<tr>\n";
	echo "<th scope=\"row\">".__( 'Active', 'google-authenticator' )."</th>\n";
	echo "<td>\n";
	echo "<div><input name=\"GA_enabled\" id=\"GA_enabled\" class=\"tog\" type=\"checkbox\"" . checked( $GA_enabled, 'enabled', false ) . "/></div>\n";
	echo "</td>\n";
	echo "</tr>\n";

	// Create URL for the Google charts QR code generator.
	$chl = urlencode( "otpauth://totp/{$GA_description}?secret={$GA_secret}" );
	$qrcodeurl = "https://chart.googleapis.com/chart?cht=qr&amp;chs=300x300&amp;chld=H|0&amp;chl={$chl}";

	if ( $is_profile_page || IS_PROFILE_PAGE ) {
		echo "<tr>\n";
		echo "<th><label for=\"GA_description\">".__('Description','google-authenticator')."</label></th>\n";
		echo "<td><input name=\"GA_description\" id=\"GA_description\" value=\"{$GA_description}\"  type=\"text\" /><span class=\"description\">".__(' Description that you\'ll see in the Google Authenticator app on your phone.','google-authenticator')."</span><br /></td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th><label for=\"GA_secret\">".__('Secret','google-authenticator')."</label></th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_secret\" id=\"GA_secret\" value=\"{$GA_secret}\" readonly=\"true\"  type=\"text\"  />";
		echo "<input name=\"GA_newsecret\" id=\"GA_newsecret\" value=\"".__("Create new secret",'google-authenticator')."\"   type=\"button\" class=\"button\" />";
		echo "<input name=\"show_qr\" id=\"show_qr\" value=\"".__("Show/Hide QR code",'google-authenticator')."\"   type=\"button\" class=\"button\" onclick=\"jQuery('#GA_QR_INFO').toggle('slow');\" />";
		echo "</td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th></th>\n";
		echo "<td><div id=\"GA_QR_INFO\" style=\"display: none\" >";
		echo "<img id=\"GA_QRCODE\"  src=\"{$qrcodeurl}\" alt=\"QR Code\"/>";
		echo '<span class="description"><br/> ' . __( 'Scan this with the Google Authenticator app.', 'google-authenticator' ) . '</span>';
		echo "</div></td>\n";
		echo "</tr>\n";

	}


	echo "</tbody></table>\n";
	echo "<script type=\"text/javascript\">\n";
	echo "var GAnonce='".wp_create_nonce('GoogleAuthenticatoraction')."';\n";
  	echo <<<ENDOFJS
	jQuery('#GA_newsecret').bind('click', function() {
		var data=new Object();
		data['action']	= 'GoogleAuthenticator_action';
		data['nonce']	= GAnonce;
		jQuery.post(ajaxurl, data, function(response) {
  			jQuery('#GA_secret').val(response['new-secret']);
  			chl=escape("otpauth://totp/"+jQuery('#GA_description').val()+"?secret="+jQuery('#GA_secret').val());
  			qrcodeurl="https://chart.googleapis.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
  			jQuery('#GA_QRCODE').attr('src',qrcodeurl);
  			jQuery('#GA_QR_INFO').show('slow');
  		});  	
	});  
	
	jQuery('#GA_description').bind('focus blur change keyup', function() {
  		chl=escape("otpauth://totp/"+jQuery('#GA_description').val()+"?secret="+jQuery('#GA_secret').val());
  		qrcodeurl="https://chart.googleapis.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
  		jQuery('#GA_QRCODE').attr('src',qrcodeurl);
	});
	
</script>
ENDOFJS;
		
}

/**
 * Form handling of Google Authenticator options added to personal profile page (user editing his own profile)
 */
function personal_options_update() {
	global $user_id;

	$GA_enabled		= trim( $_POST['GA_enabled'] );
	$GA_secret		= trim( $_POST['GA_secret'] );
	$GA_description	= trim( $_POST['GA_description'] );
	
	if ( '' == $GA_enabled )
		$GA_enabled = 'disabled';
    else
		$GA_enabled = 'enabled';
	
	update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
	update_user_option( $user_id, 'googleauthenticator_secret', $GA_secret, true );
	update_user_option( $user_id, 'googleauthenticator_description', $GA_description, true );
}

/**
 * Extend profile page with ability to enable/disable Google Authenticator authentication requirement.
 * Used by an administrator when editing other users.
 */
function edit_user_profile() {
	global $user_id;
	$GA_enabled = trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	echo "<h3>".__('Google Authenticator Settings','google-authenticator')."</h3>\n";
	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";
	echo "<tr>\n";
	echo "<th scope=\"row\">".__('Active','google-authenticator')."</th>\n";
	echo "<td>\n";
	echo "<div><input name=\"GA_enabled\" id=\"GA_enabled\"  class=\"tog\" type=\"checkbox\"" . checked( $GA_enabled, 'enabled', false ) . "/>\n";
	echo "</td>\n";
	echo "</tr>\n";
	echo "</tbody>\n";
	echo "</table>\n";
}

/**
 * Form handling of Google Authenticator options on edit profile page (admin user editing other user)
 */
function edit_user_profile_update() {
	global $user_id;
	
	$GA_enabled	= trim( $_POST['GA_enabled'] );

	if ( '' == $GA_enabled )
		$GA_enabled = 'disabled';
    else
		$GA_enabled = 'enabled';

	update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
}


/**
* AJAX callback function used to generate new secret
*/
function ajax_callback() {
	global $user_id;

	// Some AJAX security
	check_ajax_referer( 'GoogleAuthenticatoraction', 'nonce' );
	
	// Create new secret, using the users password hash as input for further hashing
	$secret = $this->create_secret();

	$result = array( 'new-secret' => $secret );
	header( 'Content-Type: application/json' );
	echo json_encode( $result );

	// die() is required to return a proper result
	die(); 
}

} // end class

new GoogleAuthenticator;
?>