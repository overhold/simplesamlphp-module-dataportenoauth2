<?php

use \SimpleSAML\Utils\HTTP;
use Zend\Http\Request;
use Kasperrt\OAuth2;

class sspmod_dataportenoauth2_Auth_Source_Connect extends SimpleSAML_Auth_Source {

  /**
   * Client ID
   */
  protected $client_id;

  /**
   * Client Secret
   */
  protected $client_secret;

  /**
   * Auth endpoint
   */
  static $auth_endpoint = "https://auth.dataporten.no/oauth/authorization";

  /**
   * Token endpoint
   */
  static $token_endpoint = "https://auth.dataporten.no/oauth/token";

  /**
   * Userinfo endpoint
   */
  static $user_endpoint = "https://auth.dataporten.no/userinfo";

  /**
   * Constructor for this authenicator source
   *
   * @param array $info Information about this authentication source.
   * @param array $config Config for this authentication source.
   */
  public function __construct($info, $config) {
    parent::__construct($info, $config);

    $this->client_id = $config['client_id'];
    $this->client_secret = $config['client_secret'];

  }

  protected function getConfig() {
    return array(
      'client_id' => $this->client_id,
      'redirect_uri' => SimpleSAML_Module::getModuleURL('dataportenoauth2/resume.php'),
      'auth' => self::auth_endpoint,
      'token' => self::token_endpoint,
      'user' => self::user_endpoint,
    );
  }

  /**
   * Log in using an external authentication helper
   *
   * @param array &$state Information about the current authentication
   */
  public function authenticate(&$state) {
    $state['dataportenoauth2:AuthID'] = $this->authId;
    $state_id = SimpleSAML_Auth_State::saveState($state, 'dataportenoauth2:Connect', TRUE);
    $info = $this->getConfig($state_id);
    HTTP::redirectTrustedURL($info['auth'], array(
      "client_id"     => $info["client_id"],
      "redirect_uri"  => $info["redirect_uri"],
      "response_type" => "code",
      "state"         => $stateId
    ));
  }

  /**
  *
  * Returns the equivalent of Apache's $_SERVER['REQUEST_URI'] variable.
  *
  * Because $_SERVER['REQUEST_URI'] is only available on Apache, we generate an equivalent using other environment variables.
  *
  * Taken from Drupal.
  * @see https://api.drupal.org/api/drupal/includes!bootstrap.inc/function/request_uri/7
  */
  public static function requesturi() {
    if (isset($_SERVER['REQUEST_URI'])) {
      $uri = $_SERVER['REQUEST_URI'];
    }
    else {
      if (isset($_SERVER['argv'])) {
        $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['argv'][0];
      }
      elseif (isset($_SERVER['QUERY_STRING'])) {
        $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['QUERY_STRING'];
      }
      else {
        $uri = $_SERVER['SCRIPT_NAME'];
      }
    }
    // Prevent multiple slashes to avoid cross site requests via the Form API.
    $uri = '/' . ltrim($uri, '/');

    return $uri;
  }

  protected static function getAttributes($user) {
    return array(
      'uid'     => $user['userid'] ? $user['userid'] : $user['user']['userid'] ? $user['user']['userid'] : "",
      'mail'    => $user['email'] ? $user['email'] : $user['user']['email'] ? $user['user']['email'] : "",
      'picture' => $user['picture'] ? $user['picture'] : $user['user']['picture'] ? $user['user']['picture'] : "",
      'name'    => $user['name'] ? $user['name'] : $user['user']['name'] ? $user['user']['name'] : "",
    ) + $user;
  }

  public static function resume() {
    $request = Request::fromString($_SERVER['REQUEST_METHOD'] . ' ' . self::requesturi());
    if (!$stateId = $request->getQuery('state')) {
      throw new SimpleSAML_Error_BadRequest('Missing "state" parameter.');
    }
    $state = SimpleSAML_Auth_State::loadState($stateId, 'dataportenoauth2:Connect');
    /*
     * Now we have the $state-array, and can use it to locate the authentication
     * source.
     */
    $source = SimpleSAML_Auth_Source::getById($state['dataportenoauth2:AuthID']);
    if ($source === NULL) {
      /*
       * The only way this should fail is if we remove or rename the authentication source
       * while the user is at the login page.
       */
      throw new SimpleSAML_Error_Exception('Could not find authentication source.');
    }

    if(!$code = $request->getQuery('code')) {
      /**
       * Throwing error if no code is being sent.
       */
       throw new SimpleSAML_Error_Exception('No code was sent from origin.');
    }

    /*
     * Make sure that we haven't switched the source type while the
     * user was at the authentication page. This can only happen if we
     * change config/authsources.php while an user is logging in.
     */
    if (! ($source instanceof self)) {
      throw new SimpleSAML_Error_Exception('Authentication source type changed.');
    }

    $ouath_client = new OAuth2($source->getConfig());
    $access_token = $oauth_client->get_access_token($code);
    $identity     = $oauth_client->get_identity($access_token);
    if(count($identity) < 1) {
      /**
       * The user isn't authenticated
       */
      throw new SimpleSAML_Error_Exception('User not authenticated after login attempt.', $e->getCode(), $e);
    }
    $state['Attributes'] = self:getAttributes($identity);
    SimpleSAML_Auth_Source::completeAuth($state);
    /*
     * The completeAuth-function never returns, so we never get this far.
     */
    assert('FALSE');
  }
}
