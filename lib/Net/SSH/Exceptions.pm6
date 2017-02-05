unit module Net::SSH::Exceptions;
use v6.c;

subset StrInt of Any where Str | Int;

class X::SSH is Exception { }

class X::SSH::Init is X::SSH {

    method message(){
        "Failed to initialize SSH";
    }
}

class X::SSH::Connect is X::SSH {
    has Str $.host is required;
    has StrInt $.error is required;

    method message(){
        "Failed to connect to $.host: $.error";
    }
}

class X::SSH::TimeoutConnect is X::SSH {
    has Str $.host is required;
    has Numeric $.timeout is required;

    method message(){
        "Failed to connect to $.host: timeouted $.timeout sec";
    }
}

class X::SSH::Auth is X::SSH {
    has Str $.host is required;
    has Str $.type = 'unknown';
    has StrInt $.error is required;

    method message(){
        "Authentication failed with '$.type' login: $.error";
    }
}

class X::SSH::Channel is X::SSH {
    has Str $.host is required;

    method message(){
        "Failed to open channel to $.host";
    }
}

class X::SSH::Disconnected is X::SSH {

    method message(){
        "Cannot handle disconnected session";
    }
}

class X::SSH::Blocked is X::SSH {

    method message(){
        "Blocked by another operation";
    }
}

class X::SSH::Exec is X::SSH {
    has Str $.host is required;
    has Str $.cmd is required;
    has StrInt $.error is required;
    has Str $.stage = 'init';
	has int $.exitcode = -1;

    method message(){
        "Failed to execute '$.cmd' at stage '$.stage' exitcode '$.exitcode': $.error";
    }
}

