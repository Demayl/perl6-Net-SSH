unit class Net::SSH;

use v6.c;
use NativeCall;
use Net::SSH::LibSSH;
use Net::SSH::Exceptions;
use Net::SSH::Response;
use Net::SSH::Channel;

# WIP Module, do not use

subset Port of Int where 0 < * <= 65535 ;
subset NULL of Nil;

has Str $.host is required;
has Int $.port = 22;
has Str $.user;
has Int $.timeout;
has Numeric $.connect-timeout where 0 < * < 120;

has Pointer $!sess;
has Pointer $!channel;
has int32   $!rc = -1;

#submethod BUILD(:$!host, :$!port=22, :$!user?, :$!timeout?) {
#    say "Initialized";
#}

method connect(Str $host?) {
    $.host = $host if $host.defined;
    $!sess = ssh_new();

    if $!sess.Bool == False {
        fail X::SSH::Init.new();
    }

    ssh_options_set($!sess, SSH_OPTIONS_HOST, $.host);
    ssh_options_set($!sess, SSH_OPTIONS_PORT_STR, $.port.Str);
    ssh_options_set($!sess, SSH_OPTIONS_USER, $.user) if $.user;
    ssh_options_set($!sess, SSH_OPTIONS_TIMEOUT, my long $.timeout) if $.timeout;
#    ssh_options_set($!sess, SSH_OPTIONS_LOG_VERBOSITY, SSH_LOG_PACKET.Str);

    # TODO SSH_OPTIONS_TIMEOUT is ignored in libssh, so timeout here. NOTE we cannot call free() untill done
    $!rc = ssh_connect($!sess);

    if $!rc != SSH_OK {
        self!disconnect;
        fail X::SSH::Connect.new( :$.host, :error(self!get_error) );
    }
}

multi method login( Str :$user?, Str:D :$password ) returns Bool {
    $!rc = ssh_userauth_password($!sess,$user,$password);

    if $!rc != SSH_AUTH_SUCCESS {
        self!disconnect;
        note X::SSH::Auth.new( :$.host, :error(self!get_error), :type('user-pass') );
        return False;
    }

    return True;
}

# TODO add more pub-key logins
# Try auto SSH agent
multi method login(Bool :$ssh_agent, Str :$user?, Str :$password?) returns Bool {
    $!rc =  ssh_userauth_publickey_auto($!sess,$user,$password);

    if $!rc != SSH_AUTH_SUCCESS {
        self!disconnect;
        note X::SSH::Auth.new( :$.host, :error(self!get_error), :type('public key') );
        return False;
    }

    return True;
}

# without password
multi method login(Str :$user?) returns Bool {
    $!rc = ssh_userauth_none($!sess,$user);

    if $!rc != SSH_AUTH_SUCCESS {
        self!disconnect;
        note X::SSH::Auth.new( :$.host, :error(self!get_error), :type('password-less') );
        return False;
    }

    return True;
}

multi method run( Str $cmd, Bool :$async where *.so ) {
    fail "Not supported ... yet";
    return Promise.start({ self.run($cmd) });
}

# Run command and return exitcode only
# Param Str $command to execute
# Return Int $exitcode : -1 on error
multi method run( Str $cmd ) returns Int {
    my $channel := Net::SSH::Channel.new( :$!sess, :$.host );

    if $channel.exec( $cmd ) {

        my int32 $code = $channel.exitcode;
        $channel.close;
        return $code;
    }

    $channel.close;

    return -1;
}

method exec( Str $cmd, Bool :$stderr is copy = False, Bool :$merge = False ){
    my $channel := Net::SSH::Channel.new( :$!sess, :$.host );

    if !$channel.exec( $cmd ) {
        return NULL;
    }

    my ( $STDOUT, $STDERR ) = $channel.read();

    if $STDOUT.defined.not {
        note X::SSH::Exec.new( :$.host, :$cmd, :error(self!get_error), :stage('read') );
        return Nil;
    }

    my int $exitcode = $channel.exitcode( );

    if so $merge {
        $STDOUT.append: $STDERR ;
        $STDERR = Buf.new;
    }

    my $response := Net::SSH::Response.new( :$STDERR, :$STDOUT, :$exitcode, :$channel );

    return $response;
}

method !new_channel {

    self!close_channels() if $!channel.Bool;

    $!channel = ssh_channel_new($!sess);

    if $!channel.Bool == False {
        self!close_channels;
        fail X::SSH::Channel.new( :$.host );
    }

    my int $res = ssh_channel_open_session($!channel);

    if $res != SSH_OK {
        self!close_channels;
        fail X::SSH::Channel.new( :$.host );
    }

    return $!channel;
}

method !disconnect() {
    ssh_disconnect($!sess) if $!rc == 0;
    ssh_free($!sess);
}

method !close_channels( Pointer $channel = $!channel ) {

    ssh_channel_close( $channel ) if $channel.Bool;
    ssh_channel_send_eof( $channel ) if $channel.Bool;
    ssh_channel_free(  $channel ) ;
}

method close {
    self!close_channels;
    self!disconnect;
}

method !get_error() {
#    my $bytes = nativecast( CArray[int8], ssh_get_error($!sess) ) ;
#    say $bytes[0];
    #my $buf = Buf.new( $bytes[0..($size*$nmemb-1)] );
#    say $bytes;
    return ssh_get_error($!sess);
}

method !get_error_code() returns int32 {
    return ssh_get_error_code($!sess);
}

method !init_channel() {

}

# NOTE DESTROY is ignored ?
method DESTROY {
    say "DESTROY module";
    self!disconnect();
}

