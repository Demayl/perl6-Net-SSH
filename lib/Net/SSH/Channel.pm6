unit class Net::SSH::Channel;
use v6.c;
use NativeCall;
use Net::SSH::LibSSH;
use Net::SSH::Exceptions;

has Pointer $!channel;
has Pointer $.sess;
has Str $.host;
has Bool $.debug is required;
has Bool $.bin is required;
has Supplier $!supply .= new;
has Numeric $!read-chunk-poll-sleep = 0.1;
has Str $!cmd;

subset BufferSize of Int where -> $i { $i > 0 && ($i +& ($i-1)) == 0 }  ; # Buffers can be only power of 2

submethod BUILD( :$!sess, :$!host, :$!bin, :$!debug ){

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

# Actual supply
method Supply {
	return $!supply.Supply;
}

method exec(Str $cmd) {

	$!cmd = $cmd;
    my int $nbytes;
    my int $res     = ssh_channel_request_exec($!channel, $cmd);

    if $res != SSH_OK {
        note X::SSH::Exec.new( :$.host, :$cmd, :error(self!get_error) );
        self.close;
        return Nil;
    }

    return True;
}

method !read-sync( Buf :$STDOUT! is rw, Buf :$STDERR! is rw, Bool :$stderr = False, BufferSize :$buffer-size = 256 ) {

    my $buffer      = CArray[int8].new;
    $buffer[$buffer-size-1]    = 0;

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
method read(BufferSize :$buffer-size = 256 ) returns Promise {
    my Int $nbytes;

    my Buf $STDOUT .= new;
    my Buf $STDERR .= new;

	my Promise $promise = start {

		while !self!eof { # While stream is active we can read
			my $buffer      = CArray[int8].new;
			$buffer[$buffer-size-1]    = 0;

			$nbytes = ssh_channel_read_nonblocking($!channel, $buffer, $buffer.elems, 0);
			if $nbytes < 0 { # Error read ( it can indicate error execute )

				self.close; # TODO Raise exception
				say "[RCV][ERROR] recieved <0 bytes: $nbytes" if self.debug;
				$!supply.quit( X::SSH::Exec.new( :$!host, :error( self!get_error ), :stage('AFTER'), :cmd($!cmd) ) );
			} elsif $nbytes > 0 {
				say "[RCV] bytes: $nbytes" if self.debug;
				if $nbytes != $buffer.elems {
					$buffer = CArray[int8].new( $buffer.list[0..$nbytes-1] );
					$nbytes = 0; # LAST read - do not try more
				}

				$!supply.emit( Buf.new( $buffer.list ) ) if self.bin; # Emit raw bin data
				$!supply.emit( Buf.new( $buffer.list ).decode ) if !self.bin;
			}

			my int32 $poll-result = ssh_channel_poll($!channel, 0); # Check if more data can be read, else sleep a bit
			if $poll-result == 0 {
				sleep $!read-chunk-poll-sleep;
			}
			if $poll-result < 0 { # Error
				fail X::SSH::Exec.new( :$!host, :error('FAIL'), :stage('after'), :cmd('test') );
				last;
			}
		}
		say "DONE";
		$!supply.done(); # Nothing to read more
	};
#	await $promise;

	return $promise;
}

method !eof returns Bool {
	return ssh_channel_is_eof( $!channel ) != 0;
}

method !is_open returns Bool {

	return ssh_channel_is_open( $!channel ) == 0;
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
