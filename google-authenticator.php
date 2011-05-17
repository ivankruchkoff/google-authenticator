<?php
/*
Plugin Name: Google Authenticator
Plugin URI: http://henrik.schack.dk/google-authenticator-for-wordpress
Description: Multi-Factor Authentication for Wordpress using the Android/Iphone/Blackberry app as One Time Password generator.
Author: Henrik Schack
Version: 0.20
Author URI: http://henrik.schack.dk/
Compatibility : WordPress 3.1.2
Text Domain: google-auth
Domain Path: /lang

----------------------------------------------------------------------------

	Thanks to Bryan Ruiz for his Base32 encode/decode class, found at php.net
	
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

require_once('base32.php');


/**
 * Check the verification code entered by the user.
 */
function GoogleAuthenticate($secretkey,$thistry) {
	
	$tm=intval(time()/30);
	
	$secretkey=Base32::decode($secretkey);
	// Keys from 30 seconds before and after are valid aswell.
	for ($i=-1; $i<2; $i++) {
		// Pack time into binary string
		$time=chr(0).chr(0).chr(0).chr(0).pack('N*',$tm+$i);
		// Hash it with users secret key
		$hm=hash_hmac ('SHA1' ,$time, $secretkey,true);
		// Use last nipple of result as index/offset
		$offset = ord(substr($hm,-1)) & 0x0F;
		// grab 4 bytes of the result
		$hashpart=substr($hm,$offset,4);
		// Unpak binary value
		$value=unpack("N",$hashpart);
		$value=$value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;
		$value = bcmod($value,1000000) ;
		if ($value == $thistry) {
			return true;
		}
	}
	return false;
}

/**
 * Create a new secret for the Google Authenticator app.
 * Hash the current time, with the hash of the users password
 * then grap 10 bytes of the result using lower nipple as offset
 * into the datastring.
 */ 
function GoogleAuthenticator_create_secret($inputvalue) {
	$rawsecret = hash_hmac('SHA256',microtime(),$inputvalue,true);
	$offset = ord(substr($rawsecret,-1)) & 0x0F;
	$secret = substr($rawsecret,$offset,10);
	return Base32::encode($secret);
}


/**
 * Add verification code field to login form.
 */
function GoogleAuthenticator_loginform() {
  echo "\t<p>\n";
  echo "\t\t<label><a href=\"http://code.google.com/p/google-authenticator/\" target=\"_blank\" title=\"".__('If You don\'t have Google Authenticator enabled for Your Wordpress account, leave this field empty.','google-auth')."\">".__('Google Authenticator code','google-auth')."</a><span id=\"google-auth-info\"></span><br />\n";
  echo "\t\t<input type=\"password\" name=\"otp\" id=\"user_email\" class=\"input\" value=\"\" size=\"20\" tabindex=\"25\" /></label>\n";
  echo "\t</p>\n";
}


/**
 * Login form handling.
 * Check Google Authenticator verification code, if user has been setup to do so.
 * @param wordpressuser
 * @return user/loginstatus
 */
function GoogleAuthenticator_check_otp( $user ) {

	// Does the user have the Google Authenticator enabled ?
	if ( trim(get_user_option('googleauthenticator_enabled',$user->ID)) == 'enabled' ) {

		// Get the users secret
		$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user->ID ) );
		
		// Get the verification code entered by the user trying to login
		$otp = intval( trim( $_POST[ 'otp' ] ) );
		
		// Valid code ?
		if (! GoogleAuthenticate( $GA_secret, $otp ) ) { 
			return false;
		}
	}	
	return $user;
}


/**
 * Extend personal profile page with Google Authenticator settings.
 */
function GoogleAuthenticator_profile_personal_options() {
	global $user_id, $is_profile_page;
	
	$GA_secret			=trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
	$GA_enabled			=trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	$GA_description		=trim( get_user_option( 'googleauthenticator_description', $user_id ) );

	// In case the user has no secret ready (new install), we create one.
	if ($GA_secret == "") {
		$GA_secret=GoogleAuthenticator_create_secret( get_user_option( 'user_pass', $user_id ) );
	}

	// Use "Wordpress blog" as default description
	if ($GA_description == "") {
		$GA_description=__("Wordpress blog",'google-auth');
	}

	echo "<h3>".__( 'Google Authenticator settings', 'google-auth' )."</h3>\n";

	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";
	echo "<tr>\n";
	echo "<th scope=\"row\">".__( 'Active', 'google-auth' )."</th>\n";
	echo "<td>\n";

	echo "<div><input name=\"GA_enabled\" id=\"GA_enabled\" class=\"tog\" type=\"checkbox\"";
	if ( $GA_enabled == 'enabled' ) {
		echo ' checked="checked"';
	}
	echo "/>";
	echo "</div>\n";

	echo "</td>\n";
	echo "</tr>\n";

	// Create URL for the Google charts QR code generator.
	$chl=urlencode("otpauth://totp/".$GA_description."?secret=".$GA_secret);
	$qrcodeurl="http://chart.apis.google.com/chart?cht=qr&amp;chs=300x300&amp;chld=H|0&amp;chl=".$chl;

	if ( $is_profile_page || IS_PROFILE_PAGE ) {
		echo "<tr>\n";
		echo "<th><label for=\"GA_description\">".__('Description','google-auth')."</label></th>\n";
		echo "<td><input name=\"GA_description\" id=\"GA_description\" value=\"".$GA_description."\"  type=\"text\" /><span class=\"description\">".__(' Description you\'ll see on your phone.','google-auth')."</span><br /></td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th><label for=\"GA_secret\">".__('Secret','google-auth')."</label></th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_secret\" id=\"GA_secret\" value=\"".$GA_secret."\" readonly=\"true\"  type=\"text\"  />";
		echo "<input name=\"GA_newsecret\" id=\"GA_newsecret\" value=\"".__("Create new secret",'google-auth')."\"   type=\"button\" class=\"button\" />";
		echo "<input name=\"show_qr\" id=\"show_qr\" value=\"".__("Show/Hide QR code",'google-auth')."\"   type=\"button\" class=\"button\" onclick=\"jQuery('#GA_QR_INFO').toggle('slow');\" />";
		echo "</td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th></th>\n";
		echo "<td><div id=\"GA_QR_INFO\" style=\"display: none\" >";
		echo "<img id=\"GA_QRCODE\"  src=\"".$qrcodeurl."\" alt=\"QR Code\"/>";
		echo "<span class=\"description\">".__('<br/>  Scan this with the Google Authenticator app.','google-auth')."</span>";
		echo "</div></td>\n";
		echo "</tr>\n";

	}


	echo "</tbody></table>\n";
	echo "<script type=\"text/javascript\">\n";
	echo "var ajaxurl='".admin_url( 'admin-ajax.php' )."'\n";
	echo "var GAnonce='".wp_create_nonce('GoogleAuthenticatoraction')."';\n";
  	echo <<<ENDOFJS
	jQuery('#GA_newsecret').bind('click', function() {
		var data=new Object();
		data['action']	= 'GoogleAuthenticator_action';
		data['nonce']	= GAnonce;
		jQuery.post(ajaxurl, data, function(response) {
  			jQuery('#GA_secret').val(response['new-secret']);
  			chl=escape("otpauth://totp/"+jQuery('#GA_description').val()+"?secret="+jQuery('#GA_secret').val());
  			qrcodeurl="http://chart.apis.google.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
  			jQuery('#GA_QRCODE').attr('src',qrcodeurl);
  			jQuery('#GA_QR_INFO').show('slow');
  		});  	
	});  
	
	jQuery('#GA_description').bind('focus blur change keyup', function() {
  		chl=escape("otpauth://totp/"+jQuery('#GA_description').val()+"?secret="+jQuery('#GA_secret').val());
  		qrcodeurl="http://chart.apis.google.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
  		jQuery('#GA_QRCODE').attr('src',qrcodeurl);
	});
	
</script>
ENDOFJS;
		
}

/**
 * Form handling of Google Authenticator options added to personal profile page (user editing his own profile)
 */
function GoogleAuthenticator_personal_options_update() {
	global $user_id;

	$GA_enabled		= trim( $_POST['GA_enabled'] );
	$GA_secret		= trim( $_POST['GA_secret'] );
	$GA_description	= trim( $_POST['GA_description'] );
	
	if ($GA_enabled !="") {
		$GA_enabled="enabled";
	} else {
		$GA_enabled="disabled";
	}
	
	update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
	update_user_option( $user_id, 'googleauthenticator_secret', $GA_secret, true );
	update_user_option( $user_id, 'googleauthenticator_description', $GA_description, true );

}

/**
 * Extend profile page with ability to enable/disable Google Authenticator authentication requirement.
 * Used by an administrator when editing other users.
 */
function GoogleAuthenticator_edit_user_profile() {
	global $user_id;
	$GA_enabled = trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	echo "<h3>".__('Google Authenticator settings','google-auth')."</h3>\n";
	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";
	echo "<tr>\n";
	echo "<th scope=\"row\">".__('Active','google-auth')."</th>\n";
	echo "<td>\n";
	echo "<div><input name=\"GA_enabled\" id=\"GA_enabled\"  class=\"tog\" type=\"checkbox\"";
	if ( $GA_enabled == 'enabled' ) {
		echo ' checked ';
	}
	echo "/>\n";
	echo "</td>\n";
	echo "</tr>\n";
	echo "</tbody>\n";
	echo "</table>\n";
}

/**
 * Form handling of Google Authenticator options on edit profile page (admin user editing other user)
 */
function GoogleAuthenticator_edit_user_profile_update() {
	global $user_id;
	
	$GA_enabled	= trim( $_POST['GA_enabled'] );
	if ( $GA_enabled != '' ) {
		update_user_option( $user_id, 'googleauthenticator_enabled', 'enabled', true );
	} else {
		update_user_option( $user_id, 'googleauthenticator_enabled', 'disabled', true );	
	}
}


/**
* AJAX callback function used to generate new secret
*/
function GoogleAuthenticator_callback() {
	global $user_id;

	// Some AJAX security
	check_ajax_referer('GoogleAuthenticatoraction', 'nonce');
	
	// Create new secret, using the users password hash as input for further hashing
	$secret=GoogleAuthenticator_create_secret( get_user_option( 'user_pass', $user_id ) );

	$result=array('new-secret'=>$secret);	
	header( "Content-Type: application/json" );
	echo json_encode( $result );

	// die() is required to return a proper result
	die(); 
}


/**
* Does the PHP installation have what it takes to use this plugin ? 
*/
function GoogleAuthenticator_check_requirements() {

	// is the SHA-1 hashing available ?
	$GoogleAuthenticatorAlgos = hash_algos();
	if ( ! in_array( "sha1", $GoogleAuthenticatorAlgos ) ) {
		return false;
	}	
	// is the SHA-256 hashing available ?
	$GoogleAuthenticatorAlgos = hash_algos();
	if ( ! in_array( "sha256", $GoogleAuthenticatorAlgos ) ) {
		return false;
	}		
	return true;
}

/**
* Prevent activation of the plugin if the PHP installation doesn't meet the requirements.
*/
function GoogleAuthenticator_activate() {
	if ( ! GoogleAuthenticator_check_requirements()) {
		die( __('Google Authenticator: Something is missing, this plugin requires the SHA1 & SHA256 Hashing algorithms to be present in your PHP installation.', 'google-auth') );
	}
}

// Initialization and Hooks
add_action('personal_options_update','GoogleAuthenticator_personal_options_update');
add_action('profile_personal_options','GoogleAuthenticator_profile_personal_options');
add_action('edit_user_profile','GoogleAuthenticator_edit_user_profile');
add_action('edit_user_profile_update','GoogleAuthenticator_edit_user_profile_update');
add_action('login_form', 'GoogleAuthenticator_loginform');	
add_action('wp_ajax_GoogleAuthenticator_action', 'GoogleAuthenticator_callback');

add_filter('wp_authenticate_user','GoogleAuthenticator_check_otp');	

register_activation_hook( __FILE__, 'GoogleAuthenticator_activate' );

load_plugin_textdomain('google-auth', false , dirname( plugin_basename(__FILE__)).'/lang' );
?>