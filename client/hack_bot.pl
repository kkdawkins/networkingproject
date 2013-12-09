#!/usr/bin/perl -w 

##Authored by kchadha 7th December 2013 ##
# a simple hack bot acts like a sniffer #

#v 0.1


use IO::Socket::INET;
use IO::Socket;

print "\n\nYou are running an IRC HACK BOT [IRC BOT V 0.1]\n";
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

print $socket "server\r\n";
                     
    # parent copies the socket to standard output
while (defined ($line = <$socket>)) {
        print STDOUT $line;
	if($line =~ /search/){
		$client_nick = substr $line, 7;
		print "Server is looking for $client_nick\nAccepting the invalid connection\n";
		print $socket "yes\r\n";
		}
	}



