<?php
namespace REST;

if ( !defined('UPLOAD_ERR_NO_TMP_DIR') ) // Introduced in PHP 5.0.3
	define('UPLOAD_ERR_NO_TMP_DIR', 6);

if ( !defined('UPLOAD_ERR_CANT_WRITE') ) // Introduced in PHP 5.1.0
	define('UPLOAD_ERR_CANT_WRITE', 7);

if ( !defined('UPLOAD_ERR_EXTENSION') ) // Introduced in PHP 5.2.0
	define('UPLOAD_ERR_EXTENSION', 8);


/**
 * Returns an error trace
 *
 * @param Exception $e
 * @return string
 */
function errorTrace($e) {
	$strTrace = '#0: '.$e->getMessage().'; File: '.$e->getFile().'; Line: '.$e->getLine()."\n";
	$i = 1;
	foreach ($e->getTrace() as $v) {
		if (!(isset($v['function']) && $v['function'] == 'errorHandle')) {
			if (isset($v['class']))
				$strTrace .= "#$i: ".$v['class'].$v['type'].$v['function'].'(';
			elseif (isset($v['function']))
				$strTrace .= "#$i: ".$v['function'].'(';
			else
				$strTrace .= "#$i: ";

			if (isset($v['args']) && isset($v['function'])) {
				$parts = array();
				foreach($v['args'] as $arg)
					$parts[] = errorArg($arg);
				$strTrace .= implode(',', $parts).') ';
			}
			if (isset($v['file']) && isset($v['line']))
				$strTrace .= '; File: '.$v['file'].'; Line: '.$v['line']."\n";
			$i++;
		}
	}
	return $strTrace;
}

/**
 * Converts any function arguement into a string
 *
 * @param mixed $arg
 * @return string
 */
function errorArg($arg, $depth=true) {
	if (is_string($arg))
		return('"'.str_replace("\n", '', $arg ).'"');
	elseif (is_bool($arg))
		return $arg ? 'true' : 'false';
	elseif (is_object($arg))
		return 'object('.get_class($arg).')';
	elseif (is_resource($arg))
		return 'resource('.get_resource_type($arg).')';
	elseif (is_array($arg)) {
		$parts = array();
		if ($depth)
			foreach ($arg as $k => $v)
				$parts[] = $k.' => '.errorArg($v, false);
		return 'array('.implode(', ', $parts).')';
	} elseif ($depth)
		return var_export($arg, true);
}
