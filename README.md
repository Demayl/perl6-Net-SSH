# Net::SSH
WIP Net::SSH module for client connections ( based on libssh ).
Use at own risk. Methods &run + &exec are working fine ( until used in a Promise/Thread )

## Synopsis
```perl6
use v6.c;
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

CATCH { # See Net::SSH::Exceptions
    when X::SSH::Connect { say "Failed to connect: " ~ .message; .resume }
    when X::SSH { say "SSH failed" } # Every Exception is X::SSH, so catch here all other Net::SSH related exceptions
    default { say "DEFAULT" }        # Something else failed
}
```

# Run a command on multiple hosts
```perl6

use v6.c;
use Net::SSH;

my Str $cmd   = 'whoami';
my Str @hosts = ('host1','host2','host3');
my Promise @promises;

for @hosts -> Str $host {

    @promises.push: start {
        my $ssh = Net::SSH.new( :$host );

        $ssh.connect;

        $ssh.login( :user('tester'), :password('www') );

        say $ssh.exec( $cmd ).out ; # BLOCK - return only exitcode

        $ssh.close();
    }
}

# wait promises to finish

await Promise.allof( @promises.flat ); # or await @promises

```

## Description
It cannot be used in Promises for now.

## TODO

- [ ] Add Supply for every exec
- [ ] Add SSH cert password option ( currently it can use only ssh-agent for certificates )
- [ ] Add scp
- [ ] Add async &exec + &run ( with option to stop them )
- [ ] Make it safer when used in Threads/Promises
- [ ] Add inline documentation
- [ ] Add tests



