unit class Net::SSH::Channel;
use v6.c;
use NativeCall;
use Net::SSH::LibSSH;
use Net::SSH::Exceptions;

has Pointer $!channel;
has Pointer $.sess;
has Str $.host;

subset BufferSize of Int where 32 < * < 1048576 ;

submethod BUILD( :$!sess, :$!host ){

    $!channel = ssh_channel_new($!sess);

    if $!channel.Bool == False {
        self.close;
        fail X::SSH::Channel.new( :$!host );
    }

    my int $res = ssh_channel_open_session($!channel);

    if $res != SSH_OK {
        self.close;
        fail X::SSH::Channel.new( :$!host );
    }

    return $!channel;
}

method exec(Str $cmd) {

    my int $nbytes;
    my int $res     = ssh_channel_request_exec($!channel, $cmd);

    if $res != SSH_OK {
        note X::SSH::Exec.new( :$.host, :$cmd, :error(self!get_error) );
        self.close;
        return Nil;
    }

    return True;
}

method !read-sync( Buf :$STDOUT! is rw, Buf :$STDERR! is rw, Bool :$stderr = False, BufferSize :$buffer-size = 255 ) {

    my $buffer      = CArray[int8].new;
    $buffer[$buffer-size]    = 0;

    my $rbytes = ssh_channel_read($!channel, $buffer, $buffer.elems, $stderr.Int);

    if $rbytes < 0 {
        self.close;
        return -1; # That actualy breaks read() method and returns Nil
    } elsif $rbytes > 0 {

        if $rbytes > 0 && $rbytes != $buffer.elems {
            $buffer = CArray[int8].new( $buffer.list[0..$rbytes-1] );
            $rbytes = 0; # LAST read - do not try more
        }

        $STDOUT.append: $buffer.list if !$stderr;
        $STDERR.append: $buffer.list if $stderr;
    }

    return $rbytes;
}

# Max 1MB buffer
method read(BufferSize :$buffer-size = 255 ) {
    my Int $nbytes;

    my Buf $STDOUT .= new;
    my Buf $STDERR .= new;

    $nbytes = self!read-sync( :$STDOUT, :$STDERR, :$buffer-size );

    if $nbytes < 0 {
        return Nil;
    }

    while $nbytes > 0 {
        $nbytes = self!read-sync( :$STDOUT, :$STDERR, :$buffer-size );
    }

    $nbytes = self!read-sync( :$STDOUT, :$STDERR, :stderr, :$buffer-size );
    while $nbytes > 0 {
        $nbytes = self!read-sync( :$STDOUT, :$STDERR, :stderr, :$buffer-size );
    }


    return ( $STDOUT, $STDERR );
}

multi method exitcode( Bool :$async where *.so ){
    state Int $code = -1;
    state Bool $set = False;
    my Int $now = -1;

    sub callback( Pointer, Pointer, Int $exitcode, Str $data ){
        $code = $exitcode ;
    }

    if !$set {
        ssh_channel_exit_status_callback( $.sess, $!channel, &callback );
        $set = True;
    }

    if $code != -1 {
        my $ret = $code ;
        $set = False;
        $code = -1 ;
        return $ret;
    }
    return -1;
}

# Blocking function
multi method exitcode {

    return ssh_channel_get_exit_status( $!channel );
}



method !get_error {
    return ssh_get_error( $!sess );
}

# NOTE temporary
method channel {
    return $!channel;
}

method close {

    ssh_channel_send_eof( $!channel )   if $!channel.Bool;
    ssh_channel_close( $!channel )      if $!channel.Bool;
    ssh_channel_free(  $!channel ) ;
}
