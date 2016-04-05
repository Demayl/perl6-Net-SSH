#!/usr/bin/env perl6
use v6.c;
use lib '.';
use Net::SSH;

my $host = 'localhost';

my $ssh = Net::SSH.new( :$host, :user('testuser') );

$ssh.connect;
$ssh.login( :password('www') );
#$ssh.login( :ssh_agent );
say $ssh.exec( "perl -E 'say 123; warn 456'", :merge ).out; # BLOCK - merge STDOUT & STDERR ( it decodes string to utf8 )
say $ssh.exec( "perl -E 'say 123'" ).STDOUT.decode("ascii"); # Get only STDOUT and decode it ( Buf ) to ascii. Usefull when output is not in utf8
say $ssh.run( "whoami" ) ; # BLOCK - return only exitcode

$ssh.close();

say now - INIT now ; # Time elapsed from the start

CATCH {
    when X::SSH { say "SSH failed" } # Every Exception is X::SSH
    when X::SSH::Connect { say "Failed to connect::" ~ .message; .resume }
    default { say "DEFAULT" }
}

