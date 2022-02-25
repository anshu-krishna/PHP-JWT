<?php
/*---------------------------------------------------------------------
 * Author: Anshu Krishna
 * Contact: anshu.krishna5@gmail.com
 * --------------------------------------------------------------------
 * call_script($method, $file, $data = NULL, $optional_headers = NULL)
 * Calls another PHP script
 *
 * @return (mixed)
 *          The function returns string containing the output of
 *          the called script or FALSE on failure.
 *
 * @param method (string)
 *          GET or POST
 *
 * @param file (mixed)
 *          (string) Filename of the called file.
 *          Note: the file must be in the same directory as the calling file.
 *          (array) With one or more key-value pairs,
 *          where keys can be domain, protocal, path and file
 *          Note: domain or path value must not have an ending '/'
 *
 * @param data (array) defaults to NULL
 *          Array containing key-value pairs to be sent as
 *          GET or POST request parameters
 *
 * @optional_headers (array) defaults to NULL
 *          Array containing key-value pairs to be sent as
 *          additional HTTP headers
 */
function call_script($method, $file, $data = NULL, $optional_headers = NULL) {
	$get_current_url_path = function() {
		$parent = parse_url($_SERVER["REQUEST_URI"]);
		return dirname($parent["path"]);
	};

	$method = strtoupper($method);
	$params = array('method' => $method);
	$optional_headers_to_send = array();
	if ($method == "POST") {
		$optional_headers_to_send["Content-type"] = "application/x-www-form-urlencoded";
	}
	$preset = array("protocal" => "http", "domain" => $_SERVER["HTTP_HOST"], "path" => $get_current_url_path(), "file" => "index.php");
	if (is_string($file))
		$preset["file"] = $file;
	elseif (is_array($file))
		$preset = array_merge($preset, $file);
	$url = "{$preset['protocal']}://{$preset['domain']}{$preset['path']}/{$preset['file']}";
	if (!is_null($data)) {
		if ($method == "POST")
			$params["content"] = http_build_query($data);
		elseif ($method == "GET")
			$url .= "?" . http_build_query($data);
	}
	if (is_array($optional_headers)) {
		$optional_headers_to_send = array_merge($optional_headers_to_send, $optional_headers);
	}
	if (count($optional_headers_to_send) > 0) {
		$optional_headers_string = array();
		foreach ($optional_headers_to_send as $key => $value) {
			$optional_headers_string[] = "$key: $value";
		}
		$params["header"] = implode("\r\n", $optional_headers_string);
	}
	$params = array($preset["protocal"] => $params);
	$response = @file_get_contents($url, false, stream_context_create($params));
	return $response;
}
?>