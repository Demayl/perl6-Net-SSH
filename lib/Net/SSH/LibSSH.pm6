unit module Net::SSH::LibSSH;

use v6.c;

use NativeCall;

constant LIB = ('ssh', v4); # requires libssh-4 to be installed


constant SSH_CRYPT  is export = 2;
constant SSH_MAC    is export = 3;
constant SSH_COMP   is export = 4;
constant SSH_LANG   is export = 5;

# auth flags 
constant SSH_AUTH_METHOD_UNKNOWN     is export = 0;
constant SSH_AUTH_METHOD_NONE        is export = 0x0001;
constant SSH_AUTH_METHOD_PASSWORD    is export = 0x0002;
constant SSH_AUTH_METHOD_PUBLICKEY   is export = 0x0004;
constant SSH_AUTH_METHOD_HOSTBASED   is export = 0x0008;
constant SSH_AUTH_METHOD_INTERACTIVE is export = 0x0010;
constant SSH_AUTH_METHOD_GSSAPI_MIC  is export = 0x0020;


# Status flags 
constant SSH_CLOSED         is export = 0x01; # Socket is closed
constant SSH_READ_PENDING   is export = 0x02; # Reading to socket won't block
constant SSH_CLOSED_ERROR   is export = 0x04; # Session was closed due to an error
constant SSH_WRITE_PENDING  is export = 0x08; # Output buffer not empty

# Error return codes
constant SSH_OK is export    = 0;     # /* No error */
constant SSH_ERROR is export = -1;    # /* Error of some kind */
constant SSH_AGAIN is export = -2;    # /* The nonblocking call must be repeated */
constant SSH_EOF   is export = -127;  # /* We have already a eof */

constant SSH_LOG_NONE  is export = 0; #/** No logging at all */
constant SSH_LOG_WARN  is export = 1; #/** Show only warnings */
constant SSH_LOG_INFO  is export = 2; #/** Get some information what's going on */
constant SSH_LOG_DEBUG is export = 3; #/** Get detailed debuging information **/
constant SSH_LOG_TRACE is export = 4; #/** Get trace output, packet information, ... */

enum ssh_kex_types_e is export <
	SSH_KEX
	SSH_HOSTKEYS
	SSH_CRYPT_C_S
	SSH_CRYPT_S_C
	SSH_MAC_C_S
	SSH_MAC_S_C
	SSH_COMP_C_S
	SSH_COMP_S_C
	SSH_LANG_C_S
	SSH_LANG_S_C
>;

enum ssh_auth_e is export (
	'SSH_AUTH_SUCCESS',
	'SSH_AUTH_DENIED',
	'SSH_AUTH_PARTIAL',
	'SSH_AUTH_INFO',
	'SSH_AUTH_AGAIN',
	SSH_AUTH_ERROR => -1
);

# messages
enum ssh_requests_e is export (
	SSH_REQUEST_AUTH => 1,
	'SSH_REQUEST_CHANNEL_OPEN',
	'SSH_REQUEST_CHANNEL',
	'SSH_REQUEST_SERVICE',
	'SSH_REQUEST_GLOBAL'
);

enum ssh_channel_type_e is export <
	SSH_CHANNEL_UNKNOWN
	SSH_CHANNEL_SESSION
	SSH_CHANNEL_DIRECT_TCPIP
	SSH_CHANNEL_FORWARDED_TCPIP
	SSH_CHANNEL_X11
>;

enum ssh_channel_requests_e is export <
	SSH_CHANNEL_REQUEST_UNKNOWN
	SSH_CHANNEL_REQUEST_PTY
	SSH_CHANNEL_REQUEST_EXEC
	SSH_CHANNEL_REQUEST_SHELL
	SSH_CHANNEL_REQUEST_ENV
	SSH_CHANNEL_REQUEST_SUBSYSTEM
	SSH_CHANNEL_REQUEST_WINDOW_CHANGE
	SSH_CHANNEL_REQUEST_X11
>;

enum ssh_global_requests_e is export <
	SSH_GLOBAL_REQUEST_UNKNOWN
	SSH_GLOBAL_REQUEST_TCPIP_FORWARD
	SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD
>;

enum ssh_publickey_state_e is export (
	SSH_PUBLICKEY_STATE_ERROR =>-1,
	SSH_PUBLICKEY_STATE_NONE  => 0,
	SSH_PUBLICKEY_STATE_VALID => 1,
	SSH_PUBLICKEY_STATE_WRONG => 2
);

###

enum ssh_server_known_e is export (
	SSH_SERVER_ERROR => -1,
	SSH_SERVER_NOT_KNOWN => 0,
	'SSH_SERVER_KNOWN_OK',
	'SSH_SERVER_KNOWN_CHANGED',
	'SSH_SERVER_FOUND_OTHER',
	'SSH_SERVER_FILE_NOT_FOUND'
);

# errors

enum ssh_error_types_e is export <
	SSH_NO_ERROR
	SSH_REQUEST_DENIED
	SSH_FATAL
	SSH_EINTR
>;


# some types for keys
enum ssh_keytypes_e is export <
  SSH_KEYTYPE_UNKNOWN
  SSH_KEYTYPE_DSS
  SSH_KEYTYPE_RSA
  SSH_KEYTYPE_RSA1
  SSH_KEYTYPE_ECDSA
>;

enum ssh_keycmp_e is export <
  SSH_KEY_CMP_PUBLIC
  SSH_KEY_CMP_PRIVATE
>;


enum ANON is export (
	'SSH_LOG_NOLOG',    # No logging at all
	'SSH_LOG_WARNING',  # Only warnings
	'SSH_LOG_PROTOCOL', # High level protocol information
	'SSH_LOG_PACKET',   # Lower level protocol infomations, packet level
	'SSH_LOG_FUNCTIONS' # Every function path
);

enum ssh_options_e is export <
  SSH_OPTIONS_HOST
  SSH_OPTIONS_PORT
  SSH_OPTIONS_PORT_STR
  SSH_OPTIONS_FD
  SSH_OPTIONS_USER
  SSH_OPTIONS_SSH_DIR
  SSH_OPTIONS_IDENTITY
  SSH_OPTIONS_ADD_IDENTITY
  SSH_OPTIONS_KNOWNHOSTS
  SSH_OPTIONS_TIMEOUT
  SSH_OPTIONS_TIMEOUT_USEC
  SSH_OPTIONS_SSH1
  SSH_OPTIONS_SSH2
  SSH_OPTIONS_LOG_VERBOSITY
  SSH_OPTIONS_LOG_VERBOSITY_STR
  SSH_OPTIONS_CIPHERS_C_S
  SSH_OPTIONS_CIPHERS_S_C
  SSH_OPTIONS_COMPRESSION_C_S
  SSH_OPTIONS_COMPRESSION_S_C
  SSH_OPTIONS_PROXYCOMMAND
  SSH_OPTIONS_BINDADDR
  SSH_OPTIONS_STRICTHOSTKEYCHECK
  SSH_OPTIONS_COMPRESSION
  SSH_OPTIONS_COMPRESSION_LEVEL
  SSH_OPTIONS_KEY_EXCHANGE
  SSH_OPTIONS_HOSTKEYS
  SSH_OPTIONS_GSSAPI_SERVER_IDENTITY
  SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY
  SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS
>;

enum (
  'SSH_SCP_WRITE', # Code is going to write/create remote files
  'SSH_SCP_READ', # Code is going to read remote files
  SSH_SCP_RECURSIVE => 0x10
);

enum ssh_scp_request_types (
  SSH_SCP_REQUEST_NEWDIR => 1,# A new directory is going to be pulled
  'SSH_SCP_REQUEST_NEWFILE',    # A new file is going to be pulled
  'SSH_SCP_REQUEST_EOF',        # End of requests
  'SSH_SCP_REQUEST_ENDDIR',     # End of directory
  'SSH_SCP_REQUEST_WARNING'     # Warning received
);

enum ssh_publickey_hash_type <
    SSH_PUBLICKEY_HASH_SHA1
    SSH_PUBLICKEY_HASH_MD5
>;


#class SSession is repr('CPointer') is export { }

### Functions

# LIBSSH_API ssh_session ssh_new(void);
sub ssh_new is native(LIB) returns OpaquePointer is export { ... }

# LIBSSH_API int ssh_options_set(ssh_session session, enum ssh_options_e type, const void *value);
sub ssh_options_set(OpaquePointer, ssh_options_e(int32), Str is rw ) is native(LIB) is symbol('ssh_options_set') returns int32 is export { ... } # 0 on success; < 0 on error
#multi sub ssh_options_set(OpaquePointer, ssh_options_e(int32), int32 is rw ) is native(LIB) is symbol('ssh_options_set') returns int32 is export { ... } # 0 on success; < 0 on error

#sub ssh_options_set_l(OpaquePointer, ssh_options_e(int32), long is rw) is native(LIB) is symbol('ssh_options_set') returns int32 is export { ... } # 0 on success; < 0 on error

sub ssh_options_set2(Pointer $sess, Int $msg, $value ) is export {
    return ssh_options_set2($sess,$msg,$value);
}

# LIBSSH_API int ssh_connect(ssh_session session);
sub ssh_connect(OpaquePointer) is native(LIB) returns int32 is export { ... }

# LIBSSH_API char * | int ssh_get_error_code(void *error);
#TODO sometime it returns -1 (int) as error message
sub ssh_get_error(OpaquePointer) is native(LIB) returns Str is encoded('utf8') is export { ... }
sub ssh_get_error_code(OpaquePointer) is native(LIB) returns int32 is export { ... }

# LIBSSH_API void ssh_free(ssh_session session);
sub ssh_free(OpaquePointer) is native(LIB) is export { ... }

sub ssh_userauth_password(OpaquePointer,Str,Str) is native(LIB) returns int32 is export { ... }
sub ssh_userauth_none(OpaquePointer,Str is rw) is native(LIB) returns int32 is export { ... }
sub ssh_userauth_publickey_auto(OpaquePointer,Str is rw,Str is rw) is native(LIB) returns int32 is export { ... }

sub ssh_disconnect(OpaquePointer) is native(LIB) is export { ... }

# CHANELS

sub ssh_channel_new(Pointer) is native(LIB) returns Pointer is export { ... }
sub ssh_channel_open_session(Pointer) is native(LIB) returns int32 is export { ... }
sub ssh_channel_request_exec(Pointer, Str) is native(LIB) returns int32 is export { ... }
sub ssh_channel_read(Pointer, CArray[int8] is rw, uint32, uint32) is native(LIB) returns int32 is export { ... }
sub ssh_channel_read_timeout(Pointer, CArray[int8] is rw, uint32, uint32,uint32) is native(LIB) returns int32 is export { ... }
sub channel_read_buffer(Pointer, CArray[int8] is rw, uint32, uint32) is native(LIB) returns int32 is export { ... }
sub ssh_channel_close(Pointer) is native(LIB) returns int32 is export { ... }
sub ssh_channel_free(Pointer) is native(LIB) returns int32 is export { ... }
sub ssh_channel_send_eof(Pointer) is native(LIB) is export { ... }
sub ssh_channel_get_exit_status(Pointer) is native(LIB) returns int32 is export { ... }
sub ssh_channel_exit_status_callback( Pointer, Pointer, &cb (Pointer, Pointer, int32 is rw, CArray[int8]) ) is native(LIB) returns int32 is export { ... }



