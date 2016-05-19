# checksigd

### remote hosted file integrity verification

## Use it:

Send a POST request to https://checksigd.herokuapp.com

Here is the most basic,

	curl -d "url=<location-of-remote-hash>" <checksigd-instance>

For example,

	curl -d "url=http://ftp.netbsd.org/pub/NetBSD/NetBSD-current/tar_files/src.tar.gz.MD5" https://checksigd.herokuapp.com
	
Returns:

	MD5 (tar_files/src.tar.gz) = e912d0ce6eec255391cc66de8772c100
	
	
	
	