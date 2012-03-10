<?php
//Vanilla Forum Login Bridge
//simpilotgroup addon module for phpVMS virtual airline system
//
//Creative Commons Attribution Non-commercial Share Alike (by-nc-sa)
//To view full license text visit http://creativecommons.org/licenses/by-nc-sa/3.0/
//
//@author David Clark (simpilot)
//@link http://www.simpilotgroup.com
//@link http://www.david-clark.net
//@copyright Copyright (c) 2012, David Clark
//@license http://creativecommons.org/licenses/by-nc-sa/3.0/

class Vanilla extends CodonModule   {

    //Place your client ID and secret here. These must match those in your jsConnect settings.
    public static $clientID = 'Your Client ID';
    public static $secret = 'Your Secret Code';
    public static $forum_url = '/forum';
    
    function __construct() {
        parent::__construct();
        
        define('JS_TIMEOUT', 24 * 60);
    }
    
    function index()    {
        //if request is coming from the login form
        if(isset($this->post->action))
        {
            $this->validate();
        }
        //its coming from the forum
        else
        {
            //Fill in the user information in a way that Vanilla can understand.
            $user = array();

            if (Auth::LoggedIn()) {
               $user['uniqueid'] = Auth::$userinfo->pilotid;
               $user['name'] = Auth::$userinfo->firstname.' '.Auth::$userinfo->lastname;
               $user['email'] = Auth::$userinfo->email;
               $user['photourl'] = SITE_URL.'/lib/avatars/'.PilotData::getPilotCode(Auth::$userinfo->code, Auth::$userinfo->pilotid).'.png';
            }

            // This should be true unless you are testing.
            $secure = true;
            
            //Generate the jsConnect string.
            $this->WriteJsConnect($user, $_GET, self::$clientID, self::$secret, $secure);
        }
    }

    function login()    {
        $this->show('vanilla/vanilla_login_form');
    }
    
    //native phpVMS login script with different form and additional Vanilla Forum redirect code
    function validate()
	{
		$email = $this->post->email;
		$password = $this->post->password;
			
		if($email == '' || $password == '')
		{
			$this->set('message', 'You must fill out both your username and password');
			$this->render('vanilla_login_form.tpl');
			return false;
		}

		if(!Auth::ProcessLogin($email, $password))
		{
			$this->set('message', Auth::$error_message);
			$this->render('vanilla_login_form.tpl');
			return false;
		} else {
            
			if(Auth::$pilot->confirmed == PILOT_PENDING) {
				$this->render('login_unconfirmed.tpl');
				Auth::LogOut();
				
				// show error
			} elseif(Auth::$pilot->confirmed == PILOT_REJECTED) {
				$this->render('login_rejected.tpl');
				Auth::LogOut();
			} else {
				$pilotid = Auth::$pilot->pilotid;
				$session_id = Auth::$session_id;
				
				# If they choose to be "remembered", then assign a cookie
				if($this->post->remember == 'on') {
					$cookie = "{$session_id}|{$pilotid}|{$_SERVER['REMOTE_ADDR']}";
					$res = setrawcookie(VMS_AUTH_COOKIE, $cookie, time() + Config::Get('SESSION_LOGIN_TIME'), '/');
				}
				
				PilotData::updateLogin($pilotid);
				
				CodonEvent::Dispatch('login_success', 'Login');
                                
                                //Vanilla Forum Code
                                header('Location: '.SITE_URL.self::$forum_url.'/entry/jsconnect?client_id='.self::$clientID);
			}
			
			return;
		}
	}

        
        /*---------------------   END PHPVMS FUNCTIONS ------------------------------------------*/
        
        
        /**
        * This client code below is for Vanilla jsConnect single sign on.
        * @author Todd Burry <todd@vanillaforums.com>
        * @version 1.1b
        * @copyright Copyright 2008, 2009 Vanilla Forums Inc.
        * @license http://www.opensource.org/licenses/gpl-2.0.php GPLv2
        */

        //define('JS_TIMEOUT', 24 * 60); //MOVED TO CONSTRUCTOR

        /**
        * Write the jsConnect string for single sign on.
        * @param array $User An array containing information about the currently signed on user. If no user is signed in then this should be an empty array.
        * @param array $Request An array of the $_GET request.
        * @param string $ClientID The string client ID that you set up in the jsConnect settings page.
        * @param string $Secret The string secred that you set up in the jsConnect settings page.
        * @param string|bool $Secure Whether or not to check for security. This is one of these values.
        * - true: Check for security and sign the response with an md5 hash.
        * - false: Don't check for security, but sign the response with an md5 hash.
        * - string: Check for security and sign the response with the given hash algorithm. See hash_algos() for what your server can support.
        * - null: Don't check for security and don't sign the response.
        * @since 1.1b Added the ability to provide a hash algorithm to $Secure.
        */
        function WriteJsConnect($User, $Request, $ClientID, $Secret, $Secure = TRUE) {
           $User = array_change_key_case($User);

           // Error checking.
           if ($Secure) {
              // Check the client.
              if (!isset($Request['client_id']))
                 $Error = array('error' => 'invalid_request', 'message' => 'The client_id parameter is missing.');
              elseif ($Request['client_id'] != $ClientID)
                 $Error = array('error' => 'invalid_client', 'message' => "Unknown client {$Request['client_id']}.");
              elseif (!isset($Request['timestamp']) && !isset($Request['signature'])) {
                 if (is_array($User) && count($User) > 0) {
                    // This isn't really an error, but we are just going to return public information when no signature is sent.
                    $Error = array('name' => $User['name'], 'photourl' => @$User['photourl']);
                 } else {
                    $Error = array('name' => '', 'photourl' => '');
                 }
              } elseif (!isset($Request['timestamp']) || !is_numeric($Request['timestamp']))
                 $Error = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
              elseif (!isset($Request['signature']))
                 $Error = array('error' => 'invalid_request', 'message' => 'Missing signature parameter.');
              elseif (($Diff = abs($Request['timestamp'] - $this->JsTimestamp())) > JS_TIMEOUT)
                 $Error = array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.');
              else {
                 // Make sure the timestamp hasn't timed out.
                 $Signature = $this->JsHash($Request['timestamp'].$Secret, $Secure);
                 if ($Signature != $Request['signature'])
                    $Error = array('error' => 'access_denied', 'message' => 'Signature invalid.');
              }
           }

           if (isset($Error))
              $Result = $Error;
           elseif (is_array($User) && count($User) > 0) {
              if ($Secure === NULL) {
                 $Result = $User;
              } else {
                 $Result = $this->SignJsConnect($User, $ClientID, $Secret, $Secure, TRUE);
              }
           } else
              $Result = array('name' => '', 'photourl' => '');

           $Json = json_encode($Result);

           if (isset($Request['callback']))
              echo "{$Request['callback']}($Json)";
           else
              echo $Json;
        }

        function SignJsConnect($Data, $ClientID, $Secret, $HashType, $ReturnData = FALSE) {
           $Data = array_change_key_case($Data);
           ksort($Data);

           foreach ($Data as $Key => $Value) {
              if ($Value === NULL)
                 $Data[$Key] = '';
           }

           $String = http_build_query($Data, NULL, '&');
           $Signature = $this->JsHash($String.$Secret, $HashType);
           if ($ReturnData) {
              $Data['client_id'] = $ClientID;
              $Data['signature'] = $Signature;
              return $Data;
           } else {
              return $Signature;
           }
        }

        /**
        * Return the hash of a string.
        * @param string $String The string to hash.
        * @param string|bool $Secure The hash algorithm to use. TRUE means md5.
        * @return string
        * @since 1.1b
        */
        function JsHash($String, $Secure = TRUE) {
           switch ($Secure) {
              case 'md5':
              case TRUE:
              case FALSE:
                 return md5($String);
              case 'sha1':
                 return sha1($String);
                 break;
              default:
                 return hash($Secure, $String).$Secure;
           }
        }

        function JsTimestamp() {
           return time();
        }
}