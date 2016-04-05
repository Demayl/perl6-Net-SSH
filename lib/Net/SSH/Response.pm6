unit class Net::SSH::Response;
use v6.c;
use NativeCall;

has $.channel is required;
has Buf $.STDOUT is required;
has Buf $.STDERR is required;
has Int $.exitcode is required where -1 <= * < 256 = -1 ; # -1 will be returned from libssh


method out { return self.STDOUT.decode }
method err { return self.STDERR.decode }
method Str { return self.STDOUT.decode }
