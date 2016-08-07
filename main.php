<?php
/*
 * SIF Private server
 * Do most preparation before handling SIF requests
 * Copyright © 2037 Dark Energy Processor Corporation
 */

/** @@ Configuration @@ **/
// Debug environment? Comment for production environment
define("DEBUG_ENVIRONMENT", true);

// Consumer key for this server
define("CONSUMER_KEY", "lovelive_test");

// Region ID for this server
define("REGION", "392");

// Application ID for SIF
define('APPLICATION_ID', '834030294');

// Expected client version before issuing "Starting Download". Comment to disable
// If the major version (the 7 or the 3) is modified, it will issue version update instead.
// Wildcard is allowed (and Server-Version default to *.*.0 if major-version is lower or higher
define('EXPECTED_CLIENT', "7.3.*");

// Enable request logging to database. Comment to disable
//define("REQUEST_LOGGING", true);

// Enable X-Message-Code checking. Comment to disable
//define("XMESSAGECODE_CHECK", true);

// Set default timezone for this server. Comment to rely on php.ini's timezone setting
//define('DEFAULT_TIMEZONE', 'UTC');

/* Game Related */ /* ************************** */

// Unlock all event stories? Comment to disable
define('UNLOCK_ALL_EVENTSCENARIO', true);

// List of badwords. Add if necessary
define('BADWORDS_LIST', [
]);
/** !! Configuration !! **/ /* End configuration */

define("MAIN_INVOKED", true, true);

$MAINTENANCE_MODE = false;
$REQUEST_HEADERS = array_change_key_case(getallheaders(), CASE_LOWER);
$REQUEST_SUCCESS = false;
$RESPONSE_ARRAY = [];
$DATABASE = NULL;
$UNIX_TIMESTAMP = time();
$TEXT_TIMESTAMP = date('Y-m-d H:i:s', $UNIX_TIMESTAMP);


set_error_handler(function($errNo, $errStr, $errFile, $errLine)
{
	http_response_code(500);
	throw new ErrorException("$errStr in $errFile on line $errLine", $errNo);
});

set_exception_handler(function($x)
{
	http_response_code(500);
	throw $x;
});

$HANDLER_SHUTDOWN = function()
{
	global $MAINTENANCE_MODE;
	global $REQUEST_HEADERS;
	global $REQUEST_SUCCESS;
	global $RESPONSE_ARRAY;
	
	if($MAINTENANCE_MODE) exit;	// Don't do anything on maintenance
	
	header("Content-Type: application/json; charset=utf-8");
	header(sprintf("Date: %s", gmdate('D, d M Y H:i:s T')));
	
	$contents = ob_get_contents();
	error_log($contents, 4);
	
	if(!defined('DEBUG_ENVIRONMENT'))
		$contents = "";
	
	if($REQUEST_SUCCESS == false)
	{
		$output = [
			"code" => 10000,
			"message" => $contents
		];
		
		if(http_response_code() == 200)
			http_response_code(403);	// If it's not previously set, set to forbidden.
		
		ob_end_clean();
		exit(json_encode($output));
	}
	
	
	$gzip_out = false;
	
	if(isset($REQUEST_HEADERS["accept-encoding"]))
	{
		if(strpos($REQUEST_HEADERS["accept-encoding"], "gzip") >= 0)
		{
			header("Content-Encoding: gzip");
			$gzip_out = true;
		}
	}
		
	header(sprintf("status_code: %d", $RESPONSE_ARRAY["status_code"]));
	
	if(strlen($contents) > 0)
		$RESPONSE_ARRAY["message"] = $contents;
	
	ob_end_clean();
	
	$output = json_encode($RESPONSE_ARRAY);
	if(strlen($output) > 2)
	{
		header(sprintf("X-Message-Code: %s", hash_hmac("sha1", $output, "liumangtuzi")));
		header(sprintf("X-Message-Sign: %s", base64_encode(str_repeat("\x00", 128))));
		
		if($gzip_out)
			echo gzencode($output);
		else
			echo $output;
	}
	
	exit;
};

$MAIN_SCRIPT_HANDLER = function(string $BUNDLE, int& $USER_ID, $TOKEN, string $OS, int $PLATFORM_ID, string $OS_VERSION, string $TIMEZONE, string $module, $action = NULL): bool
{
	global $REQUEST_HEADERS;
	global $RESPONSE_ARRAY;
	global $DATABASE;
	global $UNIX_TIMESTAMP;
	global $TEXT_TIMESTAMP;
	
	$request_data = [];
	
	if(isset($_POST['request_data']))
	{
		if(defined("XMESSAGECODE_CHECK"))
		{
			$request_data = json_decode($_POST['request_data'], true);
			
			if($request_data === false)
			{
				echo "Invalid JSON data!";
				return false;
			}
			
			if(!isset($REQUEST_HEADERS["x-message-code"]))
			{
				echo "X-Message-Code header required!";
				http_response_code(422);
				return false;
			}
			
			if(strcmp($REQUEST_HEADERS["x-message-code"], hash_hmac("sha1", $_POST['request_data'], 'liumangtuzi')))
			{
				echo "Invalid X-Message-Code";
				http_response_code(422);
				return false;
			}
		}
		else
		{
			$request_data = json_decode($_POST['request_data'], true);
			
			if($request_data === false)
			{
				echo "Invalid JSON data!";
				return false;
			}
		}
	}
	
	if(defined("REQUEST_LOGGING"))
	{
		// TODO
	}
	
	require_once('modules/include.php');
	
	if(($TOKEN == NULL && strcasecmp($module, 'login') == 0 && strcasecmp($action ?? '', 'authkey') == 0) || token_exist($TOKEN))
	{
		/* Check if user-id present */
		if($USER_ID > 0)
		{
			$cred = $DATABASE->execute_query('SELECT login_key, login_pwd FROM `logged_in` WHERE token = ?', 's', $TOKEN)[0];
			if(count($DATABASE->execute_query('SELECT user_id FROM `users` WHERE login_key = ? AND login_pwd = ? AND user_id = ?', 'ssi', $cred[0], $cred[1], $USER_ID)) != 1)
			{
				echo 'Invalid login, password, user_id, and/or token!';
				return false;
			}
		}
		
		if(strcasecmp($module, "api") == 0)
		{
			/* variable to difference between api request or not */
			define("API_REQUEST", true);
			
			$RESPONSE_ARRAY["response_data"] = [];
			$RESPONSE_ARRAY["status_code"] = 200;
			
			/* Call all handler in order */
			foreach($request_data as $rd)
			{
				$modname = "modules/{$rd["module"]}/{$rd["action"]}.php";
				
				if(is_file($modname))
				{
					$REQUEST_DATA = $rd;
					$val = include($modname);
					
					if($val == false)
						return false;
					
					$RESPONSE_ARRAY["response_data"][] = [
						"result" => $val[0],
						"status" => $val[1],
						"commandNum" => false,
						"timeStamp" => $UNIX_TIMESTAMP
					];
				}
				else
				{
					echo "One of the handler not found: $modname";
					return false;
				}
			}
			
			return true;
		}
		else
		{	
			$modname = "modules/$module/$action.php";
				
			if(is_file($modname))
			{
				$REQUEST_DATA = $request_data;
				$val = include($modname);
				
				if($val == false)
					return false;
				
				$RESPONSE_ARRAY["response_data"] = $val[0];
				$RESPONSE_ARRAY["status_code"] = $val[1];
				
				return true;
			}
			
			echo "Handler not found! $modname", PHP_EOL;
			return false;
		}
	}
	else
	{
		echo 'Invalid token!';
		return false;
	}
};

/* Returns string if array is supplied; Returns array if string is supplied */
/* Returns false if the authorize parameter is invalid */
function authorize_function($authorize)
{
	if(is_array($authorize))
	{
		/* Assemble authorize string */
		return http_build_query($authorize);
	}
	elseif(is_string($authorize))
	{
		/* Disassemble authorize string */
		parse_str($authorize, $new_assemble);
		
		/* Check the authorize string */
		if(
			(isset($new_assemble["consumerKey"]) && strcmp($new_assemble["consumerKey"], CONSUMER_KEY) == 0) &&
			(isset($new_assemble["version"]) && strcmp($new_assemble["version"], "1.1") == 0) &&
			isset($new_assemble["nonce"]) &&
			isset($new_assemble["timeStamp"])
		)
			return $new_assemble;
		
		return false;
	}
}

/* Returns value or null if variable is not set */
function retval_null(&$var)
{
	return isset($var) ? $var : NULL;
}

if(!defined("WEBVIEW"))
{
	function main()
	{
		global $MAINTENANCE_MODE;
		global $REQUEST_HEADERS;
		global $REQUEST_SUCCESS;
		global $RESPONSE_ARRAY;
		global $DATABASE;
		global $MAIN_SCRIPT_HANDLER;
		
		// Will be modified later by the server_api handler
		$USER_ID = 0;
		$TOKEN = NULL;
		$AUTHORIZE_DATA = NULL;
		
		$MODULE_TARGET = NULL;
		$ACTION_TARGET = NULL;
		
		/* Set timezone */
		if(defined('DEFAULT_TIMEZONE'))
			date_default_timezone_set(DEFAULT_TIMEZONE);
		
		/* Check if it's maintenance */
		if(file_exists("Maintenance") || file_exists("Maintenance.txt") ||
		   file_exists("maintenance") || file_exists("maintenance.txt")
		)
		{
			header("Maintenance: 1");
			$MAINTENANCE_MODE = true;
			exit;
		}
		
		/* Check the authorize */
		if(isset($REQUEST_HEADERS["authorize"]))
			$AUTHORIZE_DATA = authorize_function($REQUEST_HEADERS["authorize"]);
		if($AUTHORIZE_DATA === false)
		{
			echo "Authorize header needed!";
			exit;
		}
		$TOKEN = retval_null($AUTHORIZE_DATA["token"]);
		
		/* Check the bundle version */
		if(!isset($REQUEST_HEADERS["bundle-version"]))
		{
			echo "Bundle-Version header needed!";
			exit;
		}
		
		/* Check if client-version is OK */
		if(isset($REQUEST_HEADERS["client-version"]))
		{
			if(defined("EXPECTED_CLIENT"))
			{
				//header("Server-Version: ".EXPECTED_CLIENT);
				$ver1 = explode('.', EXPECTED_CLIENT);
				$ver2 = explode('.', $REQUEST_HEADERS["client-version"]);
				$trigger_version_up = NULL;
				
				for($i = 0; $i < 3; $i++)
				{
					if(strcmp($ver1[$i], '*') != 0 && $ver1[$i] != $ver2[$i])
					{
						$trigger_version_up = str_replace('*', '0', EXPECTED_CLIENT);
						break;
					}
				}
				
				$trigger_version_up = $trigger_version_up ?? $REQUEST_HEADERS["client-version"] ?? EXPECTED_CLIENT;
				header("Server-Version: $trigger_version_up");
			}
			else
				header("Server-Version: {$REQUEST_HEADERS["client-version"]}");
		}
		else
		{
			echo "Client-Version header needed!";
			exit;
		}
		
		/* get the module and the action. Use different scope */
		{
			$x = explode("/", $_SERVER["REQUEST_URI"]);
			
			if(isset($x[2]))
				$MODULE_TARGET = $x[2];
			else
			{
				echo "Module needed!";
				exit;
			}
			
			if(isset($x[3]))
				$ACTION_TARGET = $x[3];
		}
		
		if(isset($REQUEST_HEADERS['user-id']) || isset($AUTHORIZE_DATA['user_id']))
		{
			if(isset($REQUEST_HEADERS['user-id']))
				if(preg_match('/\d+/', $REQUEST_HEADERS['user-id']) == 1)
					$USER_ID = intval($REQUEST_HEADERS['user-id']);
				else
				{
					echo 'Invalid user ID';
					exit;
				}
		}
		
		
		/* Load database wrapper and initialize it */
		$DATABASE = require('database_wrapper.php');
		$DATABASE->initialize_environment();
		
		/* Call handler. Parameters: bundle-version, user_id, token, os, platform-id, os-version, time-zone = "unknown", module = "api", action = NULL */
		$REQUEST_SUCCESS = $MAIN_SCRIPT_HANDLER(
			$REQUEST_HEADERS["bundle-version"],
			$USER_ID,
			$TOKEN,
			$REQUEST_HEADERS["os"] ?? "unknown",
			$REQUEST_HEADERS["platform-type"] ?? -1,
			$REQUEST_HEADERS["os-version"] ?? "unknown",
			$REQUEST_HEADERS["time-zone"] ?? "unknown",
			$MODULE_TARGET ?? "api",
			$ACTION_TARGET
		);
		
		/* Check if user id changed */
		if($USER_ID > 0)
			header("user_id: $USER_ID");
		
		/* Reassemble authorize function */
		{
			$new_authorize = [];
			
			foreach($AUTHORIZE_DATA as $k => $v)
				$new_authorize[$k] = $v;
			
			$new_authorize["requestTimeStamp"] = $new_authorize["timeStamp"];
			$new_authorize["timeStamp"] = time();
			$new_authorize["user_id"] = $USER_ID > 0 ? $USER_ID : "";
			
			if(is_string($TOKEN))
				$new_authorize["token"] = $TOKEN;
			
			header(sprintf("authorize: %s", authorize_function($new_authorize)));
		}
		
		/* Exit. Let the shutdown function do the rest */
		exit;
	}

	register_shutdown_function($HANDLER_SHUTDOWN);
	ob_start();

	main();
}

?>
