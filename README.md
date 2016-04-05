# Net::SSH
WIP Net::SSH module for client connections ( based on libssh ).
Use at own risk. Methods &run + &exec are working fine ( until used in a Promise/Thread )

## Synopsis
```perl6
use v6.c;
use lib '.';
use Net::SSH;

my $host = 'localhost';

my $ssh = Net::SSH.new( :$host, :user('testuser') );

$ssh.connect;
#$ssh.login( :password('www') );
$ssh.login( :ssh_agent );
say $ssh.exec( "perl -E 'say 123; warn 456'", :merge ).out; # BLOCK - merge STDOUT & STDERR ( it decodes string to utf8 )
say $ssh.exec( "perl -E 'say 123'" ).STDOUT.decode("ascii"); # Get only STDOUT and decode it ( Buf ) to ascii
say $ssh.run( "whoami" ) ; # BLOCK - return only exitcode

$ssh.close();

say now - INIT now ;

CATCH {
    when X::SSH { say "SSH failed" } # Every Exception is X::SSH
    when X::SSH::Connect { say "Failed to connect::" ~ .message; .resume }
    default { say "DEFAULT" }
}
```

## Description
It cannot be used in Promises for now.

## TODO

- [ ] Add SSH cert password option ( currently it can use only ssh-agent for certificates )
- [ ] Add async &exec + &run ( with option to stop them )
- [ ] Make it safer when used in Threads/Promises
- [ ] Add inline documentation
- [ ] Add tests



