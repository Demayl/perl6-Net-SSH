unit class Net::SSH::Response;
use v6.c;
use NativeCall;
use Net::SSH::Channel;

has Net::SSH::Channel $.channel is required;
has Promise $.promise is required; # In that promise data is emitted to supply
has Int $.exitcode where -1 <= * < 256 = -1;
#has Buf $.STDOUT is required;
#has Buf $.STDERR is required;
#has Int $.exitcode is required where -1 <= * < 256 = -1 ; # -1 will be returned from libssh



# Get output
method out {

	if self.channel.bin {
		return self.channel.Supply.wait;
	}
	return self.channel.Supply.wait.decode;
}

method Supply {
	self.channel.Supply;
}

method stderr {

}

method stdout {

}

method err { return self.STDERR.decode }
method Str { return self.STDOUT.decode }
