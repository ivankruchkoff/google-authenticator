<?php
/*
Plugin Name: Google Authenticator
Plugin URI: https://github.com/ivankruchkoff/google-authenticator
Description: Two-factor authentication for WordPress using Google Authenticator or any other time-based (TOTP) authenticator app.
Author: Ivan Kruchkoff
Version: 0.58
Author URI: https://github.com/ivankruchkoff
Requires at least: 4.5
Requires PHP: 7.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: google-authenticator
Domain Path: /lang

----------------------------------------------------------------------------


Thanks to Kuba (Wordfence) for responsibly disclosing an XML-RPC app password authentication bypass.
Thanks to Miguel Mendez Z for responsibly disclosing a CSRF account lockout vulnerability.
Thanks to Oleksiy for a bugfix in multisite.
Thanks to Paweł Nowacki for the Polish translation.
Thanks to Fabio Zumbi for the Portuguese translation.
Thanks to Guido Schalkx for the Dutch translation.
Thanks to Henrik Schack for creating / maintaining versions 0.20 to 0.48
Thanks to Ivan Kruchkoff for his UX improvements in user signup.
Thanks to Bryan Ruiz for his Base32 encode/decode class, found at php.net.
Thanks to Tobias Bäthge for his major code rewrite and German translation.
Thanks to Pascal de Bruijn for his relaxed mode idea.
Thanks to Daniel Werl for his usability tips.
Thanks to Dion Hulse for his bugfixes.
Thanks to Aldo Latino for his Italian translation.
Thanks to Kaijia Feng for his Simplified Chinese translation.
Thanks to Ian Dunn for fixing some depricated function calls.
Thanks to Kimmo Suominen for fixing the iPhone description issue.
Thanks to Alex Concha for some security tips.
Thanks to Sébastien Prunier for his Spanish and French translations.
Thanks to Miguel Mendez Z for responsibly disclosing and reporting a CSRF account lockout vulnerability.

----------------------------------------------------------------------------

	Versions from 0.49 onwards
	Copyright 2019 Ivan Kruchkoff

	Versions up to and including 0.48
	Copyright 2013 Henrik Schack  (email : henrik@schack.dk)

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
const SETUP_PAGE = 'google_authenticator_user_page';
protected $error_message = null;
protected $setup_secret = null; // Secret posted (with a valid nonce) to the setup page, re-shown after a wrong code.

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
	if ( ! class_exists( 'Base32' ) ) {
		require_once( 'base32.php' );
	}

    if ( ! $this->is_two_screen_signin_enabled() ) {
	    add_action( 'login_form', array( $this, 'loginform' ) );
	    add_action( 'login_footer', array( $this, 'loginfooter' ) );
    }

    add_filter( 'authenticate', array( $this, 'check_otp' ), 50, 3 );

    if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
        add_action( 'wp_ajax_GoogleAuthenticator_action', array( $this, 'ajax_callback' ) );
    }

    add_action( 'personal_options_update', array( $this, 'personal_options_update' ) );
    add_action( 'profile_personal_options', array( $this, 'profile_personal_options' ) );
    add_action( 'edit_user_profile', array( $this, 'edit_user_profile' ) );
    add_action( 'edit_user_profile_update', array( $this, 'edit_user_profile_update' ) );

	add_action( 'admin_enqueue_scripts', array( $this, 'add_qrcode_script' ) );
	add_action( 'admin_menu', array ( $this, 'add_pages' ) );
	add_action( 'network_admin_menu', array ( $this, 'add_pages' ) );
	add_action( 'current_screen', array ( $this, 'redirect_if_setup_required' ) );
	add_action( 'admin_notices', array ( $this, 'successful_signup_message' ) );
	add_action( 'load-admin_page_google_authenticator_user_page', array( $this, 'save_submitted_setup_page' ) );

    load_plugin_textdomain( 'google-authenticator', false, basename( dirname( __FILE__ ) ) . '/lang' );
}

/**
 * Whether we show Google Auth code on the login screen, or after the user has entered their username and password.
 *
 * If it's on a separate screen, it means username / passwords can still be bruteforced, but logins can't occur without 2fa
 *
 * @return bool
 */
function is_two_screen_signin_enabled() {
	$two_screen_mfa = is_multisite() ? get_site_option( 'googleauthenticator_two_screen_signin' ) : get_option( 'googleauthenticator_two_screen_signin' );
	return !! $two_screen_mfa;
}

/**
 * Check the verification code entered by the user.
 */

function verify( $secretkey, $thistry, $relaxedmode, $lasttimeslot ) {
	// Did the user enter exactly 6 digits ? (Reject signs, spaces, exponents, hex and arrays.)
	if ( ! is_string( $thistry ) || ! preg_match( '/^[0-9]{6}$/', $thistry ) ) {
		return false;
	}
	$thistry = (int) $thistry;
	// If user is running in relaxed mode, we allow more time drifting
	// ±4 min, as opposed to ± 30 seconds in normal mode.
	if ( $relaxedmode == 'enabled' ) {
		$firstcount = -8;
		$lastcount  =  8;
	} else {
		$firstcount = -1;
		$lastcount  =  1;
	}

	$tm = floor( time() / 30 );

	$secretkey = Base32::decode( $secretkey );
	if ( ! is_string( $secretkey ) || '' === $secretkey ) {
		return false;
	}
	// Keys from 30 seconds before and after are valid aswell.
	for ($i=$firstcount; $i<=$lastcount; $i++) {
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
		if ( $value === $thistry ) {
			// Check for replay (Man-in-the-middle) attack.
			// Since this is not Star Trek, time can only move forward,
			// meaning current login attempt has to be in the future compared to
			// last successful login.
			if ( $lasttimeslot >= ($tm+$i) ) {
				error_log("Google Authenticator plugin: Man-in-the-middle attack detected (Could also be 2 legit login attempts within the same 30 second period)");
				return false;
			}
			// Return timeslot in which login happened.
			return $tm+$i;
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
 * Add the script to generate QR codes.
 */
function add_qrcode_script() {
    wp_enqueue_script('jquery');
    wp_register_script('qrcode_script', plugins_url('jquery.qrcode.min.js', __FILE__),array("jquery"));
    wp_enqueue_script('qrcode_script');
}

/**
 * Add 2fa pages to menus
 */
function add_pages() {
	// No menu entry for this page
	add_submenu_page( '', esc_html__( 'Google Authenticator', 'google-authenticator' ), null, 'read', self::SETUP_PAGE, array( $this, 'user_setup_page' ) );

	// Site admin screen
	add_submenu_page( 'options-general.php', esc_html__( 'Google Authenticator', 'google-authenticator' ), esc_html__( 'Google Authenticator', 'google-authenticator' ), 'manage_options', 'google_authenticator', array( $this, 'admin_setup_page' ) );

	// Network admin screen
	add_submenu_page( 'settings.php', esc_html__( 'Google Authenticator', 'google-authenticator' ), esc_html__( 'Google Authenticator', 'google-authenticator' ), 'manage_network_options', 'google_authenticator', array( $this, 'network_admin_setup_page' ) );
}

/**
 * Determine if a user needs to setup authy 2fa
 * @return bool
 */
function user_needs_to_setup_google_authenticator() {
	$user = wp_get_current_user();
	$enabled = trim(get_user_option( 'googleauthenticator_enabled', $user->ID ) ) === 'enabled';
	if ( $enabled ) {
		return false;
	}

	$must_signup = false;
	// Check every role the user has, not only the first one, so a user with an extra
	// (e.g. administrator) role can't escape a mandatory 2FA requirement.
	$user_roles = ! empty( $user->roles ) ? (array) $user->roles : array();
	$check_single_site_admin_options = true;

	if ( is_multisite() ) {
		$roles = (array) get_site_option( 'googleauthenticator_mandatory_mfa_roles', array() );
		if ( array_intersect( $user_roles, $roles ) ) {
			$must_signup = true;
		}
		$check_single_site_admin_options = ! get_site_option( 'googleauthenticator_network_only' );
	}

	if ( ! $must_signup && $check_single_site_admin_options ) {
		$roles = (array) get_option( 'googleauthenticator_mandatory_mfa_roles', array() );
		if ( array_intersect( $user_roles, $roles ) ) {
			$must_signup = true;
		}

	}

	return apply_filters( 'google_authenticator_needs_setup', $must_signup, $user );
}

/**
 * Send users to the signup page if they must signup.
 */
function redirect_if_setup_required() {
	if ( $this->user_needs_to_setup_google_authenticator() ) {
		$screen = get_current_screen();
		$pagename = 'admin_page_' . self::SETUP_PAGE;
		if ( is_a( $screen, 'WP_Screen') && in_array( $screen->id, array( $pagename, 'profile' ) ) ) {
			return;
		}

		// Some check against super admin so they can enable/disable the plugin.
		$location = admin_url( 'admin.php?page=' . self::SETUP_PAGE );
		wp_redirect( $location);
		exit;
	}
}

/**
 * Save the GA secret if valid totp is provided
 * @return void
 */
function save_submitted_setup_page() {
	$this->error_message = null; // Reset a previous error message if it was set

	if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) ) {
		return;
	}

	check_admin_referer( 'googleauthenticator_setup', 'googleauthenticator_setup_nonce' );

	$user = wp_get_current_user();

	// This page is only for enrolling. Never let it replace the secret of an account that
	// already has Google Authenticator enabled (the profile page handles changes).
	if ( 'enabled' === trim( (string) get_user_option( 'googleauthenticator_enabled', $user->ID ) ) ) {
		return;
	}

	$secret = isset( $_POST['GA_secret'] ) && is_string( $_POST['GA_secret'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['GA_secret'] ) ) ) : '';
	$otp    = isset( $_POST['GA_otp_code'] ) && is_string( $_POST['GA_otp_code'] ) ? preg_replace( '/\s+/', '', sanitize_text_field( wp_unslash( $_POST['GA_otp_code'] ) ) ) : '';
	if ( ! $this->is_valid_secret( $secret ) || '' === $otp ) {
		return;
	}

	// Re-display the same secret if the code was wrong, so the user doesn't have to rescan.
	// Only a nonce-verified POST may set it; a secret is never taken from a URL (secret fixation).
	$this->setup_secret = $secret;
	$relaxed_mode = trim( get_user_option( 'googleauthenticator_relaxedmode', $user->ID ) );
	$relaxed_mode = 'enabled' === $relaxed_mode ? 'enabled' : 'disabled';
	if ( $timeslot = $this->verify( $secret, $otp, $relaxed_mode, '' ) ) {
		update_user_option( $user->ID, 'googleauthenticator_lasttimeslot', $timeslot, true );
		update_user_option( $user->ID, 'googleauthenticator_secret', $secret, true );
		update_user_option( $user->ID, 'googleauthenticator_enabled', 'enabled', true );
		$location = admin_url( 'index.php?googleauthenticator=enabled' );
		wp_redirect( $location );
		exit;
	};

	$this->error_message = new WP_Error( 'invalid-otp', esc_html__( "OTP code doesn't match supplied secret, please check you've configured Authenticator correctly.", 'google-authenticator' ) );
}

/**
 * Show the user a success message after we redirect them following successful google authenticator setup
 */
function successful_signup_message() {
	if ( ! empty( $_GET['googleauthenticator'] ) && 'enabled' === $_GET['googleauthenticator'] ) : ?>
		<div class="updated notice">
			<p><?php esc_html_e( 'Congratulations, you have successfully enabled Google Authenticator for your account', 'google-authenticator' ); ?></p>
		</div>

	<?php endif;
}

/**
 * Callback function to render the google authenticator setup page
 */
function user_setup_page() {
	$user = wp_get_current_user();
	$enabled = trim(get_user_option( 'googleauthenticator_enabled', $user->ID ) ) === 'enabled';
	if ( $enabled ) {
		$location = admin_url( 'index.php' );
		wp_redirect( $location );
		exit;
	}
	$error = $this->error_message;

	$app_links = array(
		array(
			'text' => __( 'iOS: Authy', 'google-authenticator' ),
			'link' => 'https://itunes.apple.com/app/authy/id494168017',
		),
		array(
			'text' => __( 'iOS: Google Authenticator', 'google-authenticator' ),
			'link' => 'https://itunes.apple.com/app/google-authenticator/id388497605',
		),
		array(
			'text' => __( 'Android: Authy', 'google-authenticator' ),
			'link' => 'https://play.google.com/store/apps/details?id=com.authy.authy',
		),
		array(
			'text' => __( 'Android: Google Authenticator', 'google-authenticator' ),
			'link' => 'https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2',
		),
		array(
			'text' => __( 'Windows Phone', 'google-authenticator' ),
			'link' => 'https://www.microsoft.com/store/p/authenticator/9nblggh08h54',
		),
		array(
			'text' => __( 'Chrome Browser', 'google-authenticator' ),
			'link' => 'https://chrome.google.com/webstore/detail/authy-chrome-extension/fhgenkpocbhhddlgkjnfghpjanffonno',
		),
		array(
			'text' => __( 'Desktop', 'google-authenticator' ),
			'link' => 'https://authy.com/download/',
		),

	);

	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Google Authenticator Settings', 'google-authenticator' ); ?></h1>
		<?php if (is_wp_error( $error ) ): ?>
			<div class="error notice"><p><?php echo esc_html( $error->get_error_message() ); ?></p></div>
		<?php endif; ?>
		<p><?php echo esc_html__( "If you haven't already done so, please install the Authy or Google Authenticator app on your mobile device from the App Store:", 'google-authenticator' ); ?></p>
		<ul>
			<?php foreach( $app_links as $app_link ): ?>
				<li><a href="<?php echo esc_url( $app_link[ 'link' ] ); ?>"><?php echo esc_html( $app_link[ 'text' ] ); ?></a></li>
			<?php endforeach; ?>
		</ul>
		<p><?php echo esc_html__( 'The easiest way to enable your account is to add an account by scanning the QR code using the app.', 'google-authenticator' ); ?></p>
		<p>
			<?php echo esc_html__( "An account can also be added by typing in the secret. After you've added your account to the App, please type the code you see on the screen into the Authenticator Code field and press the Verify Authenticator Code button.", 'google-authenticator' ); ?>
		</p>
		<p>
			<?php echo esc_html__( 'If the account setup was successful, you will be logged out, and will need to login again using your Username, Password and Authenticator code generated using the App on your mobile device.', 'google-authenticator' ); ?>
		</p>
		<form method="post">
		<?php wp_nonce_field( 'googleauthenticator_setup', 'googleauthenticator_setup_nonce' ); ?>
		<?php wp_nonce_field( 'googleauthenticator_setup', 'googleauthenticator_setup_nonce' ); ?>
		<?php $this->profile_personal_options( array(
			'show_active' => false,
			'show_relaxed_mode' => false,
			'show_description' => false,
			'show_secret_qr' => true,
			'show_secret_buttons' => false,
			'show_authenticator_code' => true,
			'show_app_password' => false,
		)); ?>
		</form>
	</div>
	<?php
}

/**
 * Save site / network wide settings
 * @param $is_network
 */
function save_submitted_admin_setup_page( $is_network ) {
	$nonce = isset( $_POST['googleauthenticator'] )
		? sanitize_text_field( wp_unslash( $_POST['googleauthenticator'] ) )
		: '';
	if ( wp_verify_nonce( $nonce, 'googleauthenticator' ) ) {
		if ( $is_network ) {
			$network_settings_only = array_key_exists( 'network_settings_only', $_POST );
			if ( current_user_can( 'manage_network_options' ) ) {
				update_site_option( 'googleauthenticator_network_only', $network_settings_only );
			}
		}
		$two_screen_mfa = isset( $_POST['two_screen_approach'] ) && 'true' === $_POST['two_screen_approach'];
		if ( is_multisite() && $is_network ) {
			if ( current_user_can( 'manage_network_options' ) ) {
				update_site_option( 'googleauthenticator_two_screen_signin', $two_screen_mfa );
			}
		} elseif ( ! $is_network ) {
			if ( current_user_can( 'manage_options' ) ) {
				update_option( 'googleauthenticator_two_screen_signin', $two_screen_mfa );
			}
		}
		$roles = isset( $_POST['roles'] ) ? (array) wp_unslash( $_POST['roles'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below.
		$roles = array_values( array_filter( array_map( 'sanitize_key', array_filter( $roles, 'is_string' ) ) ) );

		if ( $is_network ) {
			if ( current_user_can( 'manage_network_options' ) ) {
				update_site_option( 'googleauthenticator_mandatory_mfa_roles', $roles );
			}
		} else {
			// Site settings can't be changed while network-wide settings are enforced.
			$network_only = is_multisite() && get_site_option( 'googleauthenticator_network_only' );
			if ( current_user_can( 'manage_options' ) && ! $network_only ) {
				update_option( 'googleauthenticator_mandatory_mfa_roles', $roles );
			}
		}
		return true;
	}
	return false;
}

/**
 * Callback function to render the google authenticator setup page
 */
function common_admin_setup_page( $is_network = false ) {
	if ( $is_network ) {
		// get_sites() was added in WordPress 4.6; fall back to wp_get_sites() on 4.5.
		$site_ids = function_exists( 'get_sites' ) ? get_sites( 'fields=ids' ) : wp_list_pluck( wp_get_sites(), 'blog_id' );
		$roles = get_editable_roles();
		foreach( $site_ids as $site_id ) {
			switch_to_blog( $site_id );
			$roles = array_merge( $roles, get_editable_roles() );
			restore_current_blog();
		}
		$edit_enabled = true;
	} else {
		$roles = get_editable_roles();
		// Site settings are read-only while network-wide settings are enforced.
		$edit_enabled = is_multisite() ? ! get_site_option( 'googleauthenticator_network_only' ) : true;
	}
	$is_updated = $this->save_submitted_admin_setup_page( $is_network );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Google Authenticator Settings', 'google-authenticator' ); ?></h1>
		<?php if ( $is_updated ): ?>
			<?php if ( $is_network ): ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Successfullly saved your settings for the network', 'google-authenticator' ); ?></p></div>
			<?php else: ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Successfullly saved your settings for the site', 'google-authenticator' ); ?></p></div>
			<?php endif; ?>
		<?php endif; ?>
		<form method="post">
			<?php if ( $is_network ): ?>
				<h2><?php esc_html_e( 'Network Settings', 'google-authenticator' ); ?></h2>
				<p>
					<label>
						<input name="network_settings_only" type="checkbox" value="true" <?php checked( get_site_option( 'googleauthenticator_network_only' ) ); ?>>
						<?php esc_html_e( 'Only use network-wide settings, ignoring site settings.', 'google-authenticator' ); ?>
					</label>
				</p>
			<?php endif; ?>
			<?php if ( is_multisite() && $is_network || ! is_multisite() ): ?>
				<?php $two_screen_mfa = is_multisite() ? get_site_option( 'googleauthenticator_two_screen_signin' ) : get_option( 'googleauthenticator_two_screen_signin' ); ?>
			   <h2><?php esc_html_e( 'Two Screen Signin', 'google-authenticator' ); ?></h2>
				<p>
					<label>
						<input name="two_screen_approach" type="checkbox" value="true" <?php checked( $two_screen_mfa ); ?>>
						<?php esc_html_e( 'Ask for authenticator code on secondary login screen', 'google-authenticator' ); ?>
					</label>
				</p>
			<?php endif; ?>
			<h2><?php esc_html_e( 'Roles requiring Google Authenticator Enabled', 'google-authenticator' ); ?></h2>
			<?php foreach ($roles as $role_key => $role) {
				$this->show_role_checkbox( $role_key, $role, $is_network );
			}
			if ( $edit_enabled ) {
				wp_nonce_field( 'googleauthenticator', 'googleauthenticator' );
				submit_button();
			} else {
				esc_html_e( 'Network-wide settings in effect, only a super admin can modify them.', 'google-authenticator' );
				if ( current_user_can( 'manage_network' ) ) :?>
					<a href="<?php echo esc_url( network_admin_url( 'settings.php?page=google_authenticator' ) ); ?>"><?php esc_html_e( 'Change network wide Google Authenticator settings', 'google-authenticator' ); ?></a>
				<?php endif;
			}
			?>

		</form>
	</div>
	<?php
}

/**
 * Render a checkbox for a role
 * @param $role_key
 * @param $role
 * @param $is_network
 */
function show_role_checkbox( $role_key, $role, $is_network ) {
	$network_roles = get_site_option( 'googleauthenticator_mandatory_mfa_roles', array() );
	$network_only = is_multisite() && boolval( get_site_option( 'googleauthenticator_network_only' ) );
	$roles = get_option( 'googleauthenticator_mandatory_mfa_roles', array() );
	if ( $network_only ) {
		$checked = in_array( $role_key, $network_roles );
	} else {
		$checked = in_array( $role_key, array_merge( $roles, $network_roles ) );
	}

	/**
	 * Criteria under which permission field can be readonly.
	 * 1. Site must be a multisite AND
	 * Either
	 * a. googleauthenticator_network_only network option is set via /wp-admin/network/settings.php?page=google_authenticator
	 *
	 * OR
	 * b. the network option for this role is set via /wp-admin/network/settings.php?page=google_authenticator
	 */
	$readonly = is_multisite() && ( ( ! $is_network && $network_only ) || ( ! $is_network && in_array( $role_key, $network_roles ) && ! in_array( $role_key, $roles ) ) );
	$readonly_label = '';

	if ( $readonly ) {
		if ( current_user_can( 'manage_network' ) ) {
			$readonly_label = __( "Sorry, you can't disable checks for this role as it's enabled at the network level.", 'google-authenticator' );
		} else {
			$readonly_label = sprintf( __( 'Sorry, this role is enabled at the network level and can only be disabled via the <a href="%s">network settings</a>', 'google-authenticator' ), esc_url( network_admin_url( 'settings.php?page=google_authenticator' ) ) );
		}
	}

	?>
	<p><label><input name="roles[]" type="checkbox"<?php if ( $readonly ) { echo ' readonly="readonly"'; } checked( $checked, true ); ?> value="<?php echo esc_attr( $role_key ); ?>"><strong><?php echo esc_html( translate_user_role( $role[ 'name' ] ) ); ?></strong></label> <?php echo wp_kses( $readonly_label, array( 'a' => array( 'href' => array() ) ) ); ?></p>
	<?php
}

/**
 * Admin setup screen
 */
function admin_setup_page() {
	$this->common_admin_setup_page();

}

/**
 * Network admin setup screen
 */
function network_admin_setup_page() {
	$this->common_admin_setup_page( true );
}
/**
 * Add verification code field to login form.
 */
function loginform() {
    echo "\t<p>\n";
    echo "\t\t<label title=\"" . esc_attr__( 'If you don\'t have Google Authenticator enabled for your WordPress account, leave this field empty.', 'google-authenticator' ) . "\">" . esc_html__( 'Google Authenticator code', 'google-authenticator' ) . "<span id=\"google-auth-info\"></span><br />\n";
    echo "\t\t<input type=\"text\" name=\"googleotp\" id=\"googleotp\" class=\"input\" value=\"\" size=\"20\" style=\"ime-mode: inactive;\" autocomplete=\"off\" /></label>\n";
    echo "\t</p>\n";
    echo "\t<script type=\"text/javascript\">\n";
    echo "\t\tdocument.getElementById(\"googleotp\").focus();\n";
    echo "\t</script>\n";
}

/**
 * Disable autocomplete on Google Authenticator code input field.
 */
function loginfooter() {
    echo "\n<script type=\"text/javascript\">\n";
    echo "\ttry{\n";
    echo "\t\tdocument.getElementById('user_email').setAttribute('autocomplete','off');\n";
    echo "\t} catch(e){}\n";
    echo "</script>\n";
}

/**
 * Login form handling.
 * Check Google Authenticator verification code, if user has been setup to do so.
 * @param wordpressuser / WP_Error
 * @return user/loginstatus
 */
function check_otp( $user, $username = '', $password = '' ) {
	// Store result of loginprocess, so far.
	$userstate = $user;

	// Get information on user, we need this in case an app password has been enabled,
	// since the $user var only contain an error at this point in the login flow.
	if ( get_user_by( 'email', $username ) === false ) {
		$user = get_user_by( 'login', $username );
	} else {
		$user = get_user_by( 'email', $username );
	}

	// Google Authenticator isn't enabled for this account, just resume normal authentication.
	if ( ! isset( $user->ID ) || 'enabled' !== trim( (string) get_user_option( 'googleauthenticator_enabled', $user->ID ) ) ) {
		return $userstate;
	}

	// Keep errors raised by other authentication checks (lockout / captcha / security plugins).
	// Only a failed username / password check is handled below.
	if ( is_wp_error( $userstate ) && ! $this->is_credential_error( $userstate ) ) {
		return $userstate;
	}

	$otp = $this->get_submitted_otp();

	// XML-RPC / APP login with an App password (only when no verification code was sent).
	$is_api_request = defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' );
	if ( '' === $otp && $is_api_request && 'enabled' === trim( (string) get_user_option( 'googleauthenticator_pwdenabled', $user->ID ) ) ) {
		return $this->check_app_password( $user, $password );
	}

	// Too many wrong codes recently? (Checked before anything else, whatever password was sent.)
	$lockout = $this->get_otp_lockout_remaining( $user->ID );
	if ( $lockout > 0 ) {
		return $this->otp_lockout_error( $lockout );
	}

	// Only evaluate the code once the password is known to be correct. Otherwise a code could be
	// brute-forced (or a valid one consumed) without knowing the password. The response is the same
	// either way, so a wrong password and a wrong code can't be told apart.
	if ( $userstate instanceof WP_User && '' !== $otp ) {
		$GA_secret      = trim( (string) get_user_option( 'googleauthenticator_secret', $user->ID ) );
		$GA_relaxedmode = trim( (string) get_user_option( 'googleauthenticator_relaxedmode', $user->ID ) );
		$lasttimeslot   = trim( (string) get_user_option( 'googleauthenticator_lasttimeslot', $user->ID ) );

		if ( $timeslot = $this->verify( $GA_secret, $otp, $GA_relaxedmode, $lasttimeslot ) ) {
			// Store the timeslot in which login was successful.
			update_user_option( $user->ID, 'googleauthenticator_lasttimeslot', $timeslot, true );
			$this->reset_failed_otp( $user->ID );
			return $userstate;
		}

		// Correct password, wrong code: count it, and lock further attempts after too many.
		$lockout = $this->register_failed_otp( $user->ID );
		if ( $lockout > 0 ) {
			return $this->otp_lockout_error( $lockout );
		}
	}

	if ( $this->is_two_screen_signin_enabled() && ! $is_api_request ) {
		wp_logout();
		$this->secondary_login_screen();
		exit;
	}

	if ( '' === $otp ) {
		return new WP_Error( 'invalid_google_authenticator_token', __( '<strong>ERROR</strong>: Please enter your Google Authenticator code.', 'google-authenticator' ) );
	}
	return new WP_Error( 'invalid_google_authenticator_token', __( '<strong>ERROR</strong>: The username, password or Google Authenticator code is incorrect, or the code has expired.', 'google-authenticator' ) );
}

/**
 * Check an App password (XML-RPC / APP logins). The App password replaces both the
 * WordPress password and the verification code for these requests.
 *
 * @param WP_User $user     User being logged in.
 * @param string  $password Submitted password.
 * @return WP_User|WP_Error
 */
function check_app_password( $user, $password ) {
	$error        = new WP_Error( 'invalid_google_authenticator_password', __( '<strong>ERROR</strong>: The Google Authenticator password is incorrect.', 'google-authenticator' ) );
	$GA_passwords = json_decode( (string) get_user_option( 'googleauthenticator_passwords', $user->ID ) );
	if ( ! is_object( $GA_passwords ) || ! isset( $GA_passwords->password ) ) {
		return $error;
	}
	$passwordhash = is_string( $GA_passwords->password ) ? trim( $GA_passwords->password ) : '';
	$userpassword = strtoupper( preg_replace( '/\s+/', '', (string) $password ) );

	// Never accept an empty app password, and never accept a stored value that is not a
	// wp_hash_password() hash. The legacy unsalted sha1 format has been removed (CVE-2026-88759).
	if ( '' === $userpassword || ! $this->is_valid_app_password_hash( $passwordhash ) ) {
		return $error;
	}

	if ( wp_check_password( $userpassword, $passwordhash ) ) {
		return new WP_User( $user->ID );
	}
	// Wrong XMLRPC/APP password !
	return $error;
}

/**
 * Whether an authentication error is a plain username / password failure from WordPress core,
 * as opposed to an error raised by another check (lockout, captcha, ...) that must be kept.
 *
 * @param WP_Error $error Error.
 * @return bool
 */
function is_credential_error( $error ) {
	$codes = array( 'incorrect_password', 'invalid_username', 'invalid_email', 'empty_password', 'empty_username', 'application_passwords_disabled', 'application_passwords_disabled_for_user' );
	return in_array( $error->get_error_code(), $codes, true );
}

/**
 * The verification code submitted with the login form, digits only.
 *
 * @return string
 */
function get_submitted_otp() {
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login form, no nonce available. The code is validated in verify().
	if ( ! isset( $_POST['googleotp'] ) || ! is_string( $_POST['googleotp'] ) ) {
		return '';
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Missing
	return preg_replace( '/\s+/', '', sanitize_text_field( wp_unslash( $_POST['googleotp'] ) ) );
}

/**
 * Seconds left before this user may try another verification code (0 = not locked).
 *
 * @param int $user_id User ID.
 * @return int
 */
function get_otp_lockout_remaining( $user_id ) {
	$until = (int) get_user_option( 'googleauthenticator_otp_lockout_until', $user_id );
	return max( 0, $until - time() );
}

/**
 * Record a wrong verification code sent together with the correct password.
 *
 * After 5 wrong codes, further attempts are blocked for 1 minute, doubling with every
 * further wrong code up to 1 hour. This makes guessing the 6 digit code infeasible.
 * The counter resets on a successful login.
 *
 * @param int $user_id User ID.
 * @return int Lockout in seconds that now applies (0 = none).
 */
function register_failed_otp( $user_id ) {
	$failures = (int) get_user_option( 'googleauthenticator_otp_failures', $user_id ) + 1;
	update_user_option( $user_id, 'googleauthenticator_otp_failures', $failures, true );

	/**
	 * Fires after a wrong Google Authenticator code was sent with a correct password.
	 *
	 * @param int $user_id  User ID.
	 * @param int $failures Consecutive wrong codes.
	 */
	do_action( 'google_authenticator_failed_code', $user_id, $failures );

	$allowed = max( 1, (int) apply_filters( 'google_authenticator_allowed_failed_codes', 5, $user_id ) );
	if ( $failures < $allowed ) {
		return 0;
	}

	$lockout = (int) min( HOUR_IN_SECONDS, MINUTE_IN_SECONDS * pow( 2, min( 10, $failures - $allowed ) ) );
	$lockout = max( 1, (int) apply_filters( 'google_authenticator_lockout_duration', $lockout, $failures, $user_id ) );
	update_user_option( $user_id, 'googleauthenticator_otp_lockout_until', time() + $lockout, true );
	return $lockout;
}

/**
 * Clear the wrong code counter after a successful login.
 *
 * @param int $user_id User ID.
 */
function reset_failed_otp( $user_id ) {
	delete_user_option( $user_id, 'googleauthenticator_otp_failures', true );
	delete_user_option( $user_id, 'googleauthenticator_otp_lockout_until', true );
}

/**
 * Error returned while code attempts are blocked.
 *
 * @param int $seconds Seconds remaining.
 * @return WP_Error
 */
function otp_lockout_error( $seconds ) {
	$minutes = (int) ceil( $seconds / MINUTE_IN_SECONDS );
	return new WP_Error(
		'google_authenticator_too_many_attempts',
		sprintf(
			/* translators: %d: number of minutes */
			_n( '<strong>ERROR</strong>: Too many incorrect Google Authenticator codes. Please try again in %d minute.', '<strong>ERROR</strong>: Too many incorrect Google Authenticator codes. Please try again in %d minutes.', $minutes, 'google-authenticator' ),
			$minutes
		)
	);
}

/**
 * Whether a Google Authenticator secret is well formed (Base32, at least 16 characters = 80 bits).
 *
 * @param string $secret Secret.
 * @return bool
 */
function is_valid_secret( $secret ) {
	return is_string( $secret ) && 1 === preg_match( '/^[A-Z2-7]{16,}$/', $secret );
}

/**
 * Whether a stored app password value looks like a wp_hash_password() hash.
 *
 * Rejects empty values and the legacy unsalted sha1 (40 chars) / md5 (32 chars) formats.
 *
 * @param mixed $hash Stored hash.
 * @return bool
 */
function is_valid_app_password_hash( $hash ) {
	return is_string( $hash ) && strlen( $hash ) > 40;
}

/**
 * Whether the user has a real (non-empty, properly hashed) app password stored.
 *
 * Removes stale values left behind by versions up to 0.56, which could store a hash of an
 * empty string when the profile was saved before an app password was generated (CVE-2026-88759).
 *
 * @param int $user_id User ID.
 * @return bool
 */
function has_usable_app_password( $user_id ) {
	$stored = get_user_option( 'googleauthenticator_passwords', $user_id );
	if ( empty( $stored ) ) {
		return false;
	}

	$GA_passwords = json_decode( $stored );
	$hash         = ( is_object( $GA_passwords ) && isset( $GA_passwords->password ) && is_string( $GA_passwords->password ) ) ? trim( $GA_passwords->password ) : '';

	if ( ! $this->is_valid_app_password_hash( $hash ) || wp_check_password( '', $hash ) ) {
		delete_user_option( $user_id, 'googleauthenticator_passwords', true );
		return false;
	}

	return true;
}

function secondary_login_screen() {
	// phpcs:disable WordPress.Security.NonceVerification.Missing -- Re-posting the login form, no nonce available.
	$redirect_to = isset( $_POST['redirect_to'] ) && is_string( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Escaped with esc_url() below, validated by wp-login.php.
	$log         = isset( $_POST['log'] ) && is_string( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '';
	$pwd         = isset( $_POST['pwd'] ) && is_string( $_POST['pwd'] ) ? wp_unslash( $_POST['pwd'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords must not be altered.
	$rememberme  = isset( $_POST['rememberme'] ) && 'forever' === $_POST['rememberme'];
	$has_otp     = isset( $_POST['googleotp'] ) && is_string( $_POST['googleotp'] );
	$otp_empty   = $has_otp && '' === trim( wp_unslash( $_POST['googleotp'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only checked for emptiness.
	// phpcs:enable WordPress.Security.NonceVerification.Missing

	login_header( esc_html__('Secondary Login Screen', 'google-authenticator' ) );
	if ( $has_otp ) {
		if ( $otp_empty ) {
			$error_message = __( '<strong>ERROR</strong>: The Google Authenticator code is missing.', 'google-authenticator' );
		} else {
			$error_message = __( '<strong>ERROR</strong>: The username, password or Google Authenticator code is incorrect, or the code has expired.', 'google-authenticator' );
		}
		echo '<div id="login_error">' . wp_kses_post( $error_message ) . '</div>';
	}?>
	<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
		<input type="hidden" name="log" value="<?php echo esc_attr( $log ); ?>" />
		<input type="hidden" name="pwd" value="<?php echo esc_attr( $pwd ); ?>" />
		<?php if ( $rememberme ): ?>
				<input name="rememberme" type="hidden" id="rememberme" value="forever" />
		<?php endif; ?>
		<?php $this->loginform(); ?>
		<p><?php esc_html_e( 'Please enter the Google Authenticator code using the app on your device.', 'google-authenticator' ); ?></p>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Log In'); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect_to ); ?>" />
			<input type="hidden" name="testcookie" value="1" />
		</p>
	</form>
	<?php
	login_footer();
}


/**
 * Extend personal profile page with Google Authenticator settings.
 */
function profile_personal_options( $args = array() ) {
	$defaults = array(
		'show_active' => true,
		'show_relaxed_mode' => true,
		'show_description' => true,
		'show_secret_qr' => false,
		'show_secret_buttons' => true,
		'show_authenticator_code' => false,
		'show_app_password' => true,
	);

	$args = wp_parse_args( $args, $defaults );

	$user = wp_get_current_user();
	$user_id = $user->ID;

	// If editing of Google Authenticator settings has been disabled, just return
	$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
	if ( $GA_hidefromuser == 'enabled') return;
	
	$GA_secret			= trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
	$GA_enabled			= trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	$GA_relaxedmode		= trim( get_user_option( 'googleauthenticator_relaxedmode', $user_id ) );
	$GA_description		= trim( get_user_option( 'googleauthenticator_description', $user_id ) );
	$GA_pwdenabled		= trim( get_user_option( 'googleauthenticator_pwdenabled', $user_id ) );
	// We dont store the generated app password in cleartext so there is no point in trying
	// to show the user anything except from the fact that a password exists.
	// has_usable_app_password() also discards empty/legacy hashes stored by older versions.
	$GA_password		= $this->has_usable_app_password( $user_id ) ? 'XXXX XXXX XXXX XXXX' : '';

	// In case the user has no secret ready (new install), we create one, or re-use the one they just
	// posted to the setup page. Never take it from the request: a secret supplied in a link would let
	// an attacker know the victim's 2FA secret once they enroll with it (secret fixation).
	if ( '' == $GA_secret ) {
		$GA_secret = null !== $this->setup_secret ? $this->setup_secret : $this->create_secret();
	}
	
	if ( '' == $GA_description ) {
		// Super admins and users with accounts on more than one site get the network name as the helpful name,
		// everyone else gets the site that they're on
		if ( is_multisite() && ( 1 < count( get_blogs_of_user( $user_id ) ) || is_super_admin() ) ) {
			$blog_details   = get_blog_details( get_network()->id );
			$GA_description = sanitize_text_field( $blog_details ? $blog_details->blogname : get_bloginfo( 'name' ) );
		} else {
			$GA_description = sanitize_text_field( get_bloginfo( 'name' ) );
		}
	}
	
	echo "<h3>" . esc_html__( 'Google Authenticator Settings', 'google-authenticator' ) . "</h3>\n";

	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";

	if ( $args['show_active'] ) {
		echo "<tr>\n";
		echo "<th scope=\"row\">" . esc_html__( 'Active', 'google-authenticator' ) . "</th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_enabled\" id=\"GA_enabled\" class=\"tog\" type=\"checkbox\"" . checked( $GA_enabled, 'enabled', false ) . "/>\n";
		echo "</td>\n";
		echo "</tr>\n";
	}

	if ( $args['show_relaxed_mode'] ) {
		echo "<tr>\n";
		echo "<th scope=\"row\">" . esc_html__( 'Relaxed mode', 'google-authenticator' ) . "</th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_relaxedmode\" id=\"GA_relaxedmode\" class=\"tog\" type=\"checkbox\"" . checked( $GA_relaxedmode, 'enabled', false ) . "/><span class=\"description\">" . esc_html__( ' Relaxed mode allows for more time drifting on your phone clock (&#177;4 min).', 'google-authenticator' ) . "</span>\n";
		echo "</td>\n";
		echo "</tr>\n";
	}

	$show_description_style = $args['show_description'] ? '' : 'display:none';
	echo "<tr style=\"{$show_description_style}\">\n";
	echo "<th><label for=\"GA_description\">" . esc_html__( 'Description', 'google-authenticator' ) . "</label></th>\n";
	echo "<td><input name=\"GA_description\" id=\"GA_description\" value=\"" . esc_attr( $GA_description ) . "\"  type=\"text\" size=\"25\" /><span class=\"description\">" . esc_html__( ' Description that you\'ll see in the Google Authenticator app on your phone.', 'google-authenticator' ) . "</span><br /></td>\n";
	echo "</tr>\n";

	echo "<tr>\n";
	echo "<th><label for=\"GA_secret\">" . esc_html__( 'Secret', 'google-authenticator' ) . "</label></th>\n";
	echo "<td>\n";
	echo "<input name=\"GA_secret\" id=\"GA_secret\" value=\"" . esc_attr( $GA_secret) . "\" readonly=\"readonly\"  type=\"text\" size=\"25\" />";
	if ( $args['show_secret_buttons']) {
		echo "<input name=\"GA_newsecret\" id=\"GA_newsecret\" value=\"" . esc_attr__( 'Create new secret', 'google-authenticator' ) . "\"   type=\"button\" class=\"button\" />";
		echo "<input name=\"show_qr\" id=\"show_qr\" value=\"" . esc_attr__( 'Show/Hide QR code', 'google-authenticator' ) . "\"   type=\"button\" class=\"button\" onclick=\"ShowOrHideQRCode();\" />";
	}
	echo "</td>\n";
	echo "</tr>\n";

	echo "<tr>\n";
	echo "<th></th>\n";

	$qr_style = $args['show_secret_qr'] ? '' : 'display: none';
	echo "<td><div id=\"GA_QR_INFO\" style=\"{$qr_style}\" >";
	echo "<div id=\"GA_QRCODE\"/></div>";

	echo '<span class="description"><br/> ' . esc_html__( 'Scan this with the Google Authenticator app.', 'google-authenticator' ) . '</span>';
	echo "</div></td>\n";
	echo "</tr>\n";
	if ( $args['show_secret_qr']) : ?>
		<script>
		var qrcode="otpauth://totp/WordPress:"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer=WordPress";
		jQuery('#GA_QRCODE').qrcode(qrcode);
		</script>
	<?php endif;

	if ( $args['show_app_password']) {
		echo "<tr>\n";
		echo "<th scope=\"row\">" . esc_html__( 'Enable App password', 'google-authenticator' ) . "</th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_pwdenabled\" id=\"GA_pwdenabled\" class=\"tog\" type=\"checkbox\"" . checked( $GA_pwdenabled, 'enabled', false ) . "/><span class=\"description\">" . esc_html__(' Enabling an App password will decrease your overall login security.','google-authenticator')."</span>\n";
		echo "</td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th></th>\n";
		echo "<td>\n";
		echo "<input name=\"GA_password\" id=\"GA_password\" readonly=\"readonly\" value=\"" . esc_attr( $GA_password ) . "\" type=\"text\" size=\"25\" />";
		echo "<input name=\"GA_createpassword\" id=\"GA_createpassword\" value=\"" . esc_attr__( 'Create new password', 'google-authenticator' ) . "\"   type=\"button\" class=\"button\" />";
		echo "<span class=\"description\" id=\"GA_passworddesc\"> " . esc_html__(' Password is not stored in cleartext, this is your only chance to see it.','google-authenticator')."</span>\n";
		echo "</td>\n";
		echo "</tr>\n";
	}


	if ( $args['show_authenticator_code']) {
		echo "<tr>\n";
		echo "<th><label for=\"GA_otp_code\">" . esc_html__( 'Authenticator Code', 'google-authenticator' ) . "</label></th>\n";
		echo "<td><input name=\"GA_otp_code\" id=\"GA_otp_code\" type=\"text\" size=\"25\" /><span class=\"description\">" . esc_html__( 'After adding the site to your google authy account, add your authenticator code here.', 'google-authenticator' ) . "</span><br /></td>\n";
		echo "</tr>\n";
	}

	echo "</tbody></table>\n";
	if ( $args['show_authenticator_code']) {
		submit_button( esc_html__( 'Verify Authenticator Code', 'google-authenticator' ) );
	}
	echo "<script type=\"text/javascript\">\n";
	echo "var GAnonce='". esc_js( wp_create_nonce('GoogleAuthenticatoraction') )."';\n";

  	echo <<<ENDOFJS
  	//Create new secret and display it
	jQuery('#GA_newsecret').bind('click', function() {
		// Remove existing QRCode
		jQuery('#GA_QRCODE').html("");
		var data=new Object();
		data['action']	= 'GoogleAuthenticator_action';
		data['nonce']	= GAnonce;
		jQuery.post(ajaxurl, data, function(response) {
  			jQuery('#GA_secret').val(response['new-secret']);
  			var qrcode="otpauth://totp/WordPress:"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer=WordPress";
			jQuery('#GA_QRCODE').qrcode(qrcode);
 			jQuery('#GA_QR_INFO').show('slow');
  		});  	
	});

	// If the user starts modifying the description, hide the qrcode
	jQuery('#GA_description').bind('focus blur change keyup', function() {
		// Only remove QR Code if it's visible
		if (jQuery('#GA_QR_INFO').is(':visible')) {
			jQuery('#GA_QR_INFO').hide('slow');
			jQuery('#GA_QRCODE').html("");
  		}
	});

	// Create new app password
	jQuery('#GA_createpassword').bind('click',function() {
		var data=new Object();
		data['action']	= 'GoogleAuthenticator_action';
		data['nonce']	= GAnonce;
		data['save']	= 1;
		jQuery.post(ajaxurl, data, function(response) {
  			jQuery('#GA_password').val(response['new-secret'].match(new RegExp(".{0,4}","g")).join(' '));
  			jQuery('#GA_passworddesc').show();
  		});  	
	});
	
	jQuery('#GA_enabled').bind('change',function() {
		GoogleAuthenticator_apppasswordcontrol();
	});

	jQuery(document).ready(function() {
		jQuery('#GA_passworddesc').hide();
		GoogleAuthenticator_apppasswordcontrol();
	});
	
	function GoogleAuthenticator_apppasswordcontrol() {
		if (jQuery('#GA_enabled').is(':checked')) {
			jQuery('#GA_pwdenabled').removeAttr('disabled');
			jQuery('#GA_createpassword').removeAttr('disabled');
		} else {
			jQuery('#GA_pwdenabled').removeAttr('checked')
			jQuery('#GA_pwdenabled').attr('disabled', true);
			jQuery('#GA_createpassword').attr('disabled', true);
		}
	}

	function ShowOrHideQRCode() {
		if (jQuery('#GA_QR_INFO').is(':hidden')) {
			var qrcode="otpauth://totp/WordPress:"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer=WordPress";
			jQuery('#GA_QRCODE').qrcode(qrcode);
	        jQuery('#GA_QR_INFO').show('slow');
		} else {
			jQuery('#GA_QR_INFO').hide('slow');
			jQuery('#GA_QRCODE').html("");
		}
	}
</script>
ENDOFJS;
}

/**
 * Form handling of Google Authenticator options added to personal profile page (user editing his own profile)
 */
function personal_options_update() {
	global $user_id;

	// If editing of Google Authenticator settings has been disabled, just return
	$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
	if ( $GA_hidefromuser == 'enabled') return;


	$GA_enabled	= ! empty( $_POST['GA_enabled'] );
	$GA_description	= isset( $_POST['GA_description'] ) && is_string( $_POST['GA_description'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['GA_description'] ) ) ) : '';
	$GA_relaxedmode	= ! empty( $_POST['GA_relaxedmode'] );
	$GA_secret	= isset( $_POST['GA_secret'] ) && is_string( $_POST['GA_secret'] ) ? strtoupper( trim( sanitize_text_field( wp_unslash( $_POST['GA_secret'] ) ) ) ) : '';
	// Only accept a well formed Base32 secret, otherwise keep the current one.
	if ( ! $this->is_valid_secret( $GA_secret ) ) {
		$GA_secret = trim( (string) get_user_option( 'googleauthenticator_secret', $user_id ) );
	}
	$GA_pwdenabled	= ! empty( $_POST['GA_pwdenabled'] );
	$GA_password	= strtoupper( preg_replace( '/\s+/', '', isset( $_POST['GA_password'] ) && is_string( $_POST['GA_password'] ) ? sanitize_text_field( wp_unslash( $_POST['GA_password'] ) ) : '' ) );
	
	if ( ! $GA_enabled ) {
		$GA_enabled = 'disabled';
	} else {
		$GA_enabled = 'enabled';
	}

	if ( ! $GA_relaxedmode ) {
		$GA_relaxedmode = 'disabled';
	} else {
		$GA_relaxedmode = 'enabled';
	}


	if ( ! $GA_pwdenabled ) {
		$GA_pwdenabled = 'disabled';
	} else {
		$GA_pwdenabled = 'enabled';
	}
	
	// Only store password if a new one has been generated. An empty field (no password created yet)
	// or the "XXXX XXXX XXXX XXXX" placeholder (keep existing) must never be hashed and stored,
	// otherwise an empty app password would be accepted over XML-RPC (CVE-2026-88759).
	// Generated app passwords are always 16 Base32 characters (see create_secret()).
	if ( 'XXXXXXXXXXXXXXXX' !== $GA_password && preg_match( '/^[A-Z2-7]{16}$/', $GA_password ) ) {
		// Store the password in a format that can be expanded easily later on if needed.
		$GA_password = array( 'appname' => 'Default', 'password' => wp_hash_password( $GA_password ) );
		update_user_option( $user_id, 'googleauthenticator_passwords', json_encode( $GA_password ), true );
	}
	
	update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
	update_user_option( $user_id, 'googleauthenticator_description', $GA_description, true );
	update_user_option( $user_id, 'googleauthenticator_relaxedmode', $GA_relaxedmode, true );
	update_user_option( $user_id, 'googleauthenticator_secret', $GA_secret, true );
	update_user_option( $user_id, 'googleauthenticator_pwdenabled', $GA_pwdenabled, true );

}

/**
 * Extend profile page with ability to enable/disable Google Authenticator authentication requirement.
 * Used by an administrator when editing other users.
 */
function edit_user_profile() {
	global $user_id;
	$GA_enabled      = trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
	$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
	echo "<h3>" . esc_html__( 'Google Authenticator Settings', 'google-authenticator' ) . "</h3>\n";
	echo "<table class=\"form-table\">\n";
	echo "<tbody>\n";

	echo "<tr>\n";
	echo "<th scope=\"row\">" . esc_html__( 'Hide settings from user', 'google-authenticator' ) . "</th>\n";
	echo "<td>\n";
	echo "<div><input name=\"GA_hidefromuser\" id=\"GA_hidefromuser\"  class=\"tog\" type=\"checkbox\"" . checked( $GA_hidefromuser, 'enabled', false ) . "/>\n";
	echo "</td>\n";
	echo "</tr>\n";

	echo "<tr>\n";
	echo "<th scope=\"row\">" . esc_html__( 'Active', 'google-authenticator' ) . "</th>\n";
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
	
	$GA_enabled	     = ! empty( $_POST['GA_enabled'] );
	$GA_hidefromuser = ! empty( $_POST['GA_hidefromuser'] );

	if ( ! $GA_enabled ) {
		$GA_enabled = 'disabled';
	} else {
		$GA_enabled = 'enabled';
	}

	if ( ! $GA_hidefromuser ) {
		$GA_hidefromuser = 'disabled';
	} else {
		$GA_hidefromuser = 'enabled';
	}

	update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
	update_user_option( $user_id, 'googleauthenticator_hidefromuser', $GA_hidefromuser, true );

}


/**
* AJAX callback function used to generate new secret
*/
function ajax_callback() {
	global $user_id;

	// Some AJAX security.
	check_ajax_referer( 'GoogleAuthenticatoraction', 'nonce' );
	
	// Create new secret.
	$secret = $this->create_secret();

	wp_send_json( array( 'new-secret' => $secret ) );
}

} // end class

$google_authenticator = new GoogleAuthenticator;

