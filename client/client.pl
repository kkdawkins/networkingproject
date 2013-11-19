##Authored by kchadha 13th november 2013 ##
# an IRC Client #

#v 0.3

use IO::Socket::INET;
use IO::Socket;
use Thread;
use warnings;
use strict;

my ($kidpid,$line);

# auto-flush on socket
$| = 1;

print "\n\nWelcome to cs525irc_client [IRC Client V 0.3]\n";
sleep(1);
my $server = 'cs525irc.cloudapp.net';
# create a connecting socket
my $socket = new IO::Socket::INET (
    PeerHost => $server,
    PeerPort => '5000',
    Proto => 'tcp',
);
die "cannot connect to the server $!\n" unless $socket;
print "\tConnection accepted by the server\n";
sleep(1);
print "\t\tWaiting to get logged in ...... \n";
sleep(1);


my $input = <$socket>;
	chop $input;
	if ($input =~/004/){
		print "Connection established\n";
	}

die "can't fork: $!" unless defined($kidpid = fork());
if ($kidpid) {                      
    # parent copies the socket to standard output
    while (defined ($line = <$socket>)) {
        print STDOUT $line;
    }
    kill("TERM" => $kidpid);        # send SIGTERM to child
}
else {                              
    # child copies standard input to the socket
    while (defined ($line = <STDIN>)) {
        print $socket "$line\r\n";
    }
}
exit;


