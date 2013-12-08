#!/usr/bin/perl -w 

##Authored by kchadha 13th november 2013 ##
# an IRC Client #

#v 0.3


use IO::Socket::INET;
use IO::Socket;
use Thread;
use warnings;
use strict;
use English;
require Tk;
use Tk;

my ($kidpid,$line,$kidpid2,$option);
my ($msg,$msg_log,$chann);
$msg_log = "";
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
	my $ch;
	#creating files for chat log
	if($line =~ /([^:]+)/){
		$ch = $1;
		if ($line =~ /$1:Welcome*/){
	open CHAT_FILE,'>>',"$ch.txt";}}
	
		

	#creating separate terminals for chat channels
	if ($line =~ /#*:Welcome/){
	die "can't fork: $!" unless defined($kidpid2 = fork());
		if($kidpid2){	
			if($line =~ /([^:]+)/){	#finding channel name
			$chann = $1;
			}
			my $chat_log;
			my $main = MainWindow->new();
			$main->minsize(500,250);
			$main->title("Channel #test");
			$main->configure(-background=>'cyan');
			our $chat_box = $main->Entry()->pack(
				-side => 'bottom',
				-ipadx => 80,
				-ipady => 10,
				-anchor => 'sw',
				-padx => 10,
				-pady => 10
				);
			my $send_button = $main->Button(-text => 'Send',
	      		-command => \&chat_box
				)->place(
					-relx => 0.70,
					-rely => 0.82,
					);

			
			sub chat_box{
			$msg = $chat_box->get();
			
			open CHAT_FILE,'>>',"$chann.txt";
			print CHAT_FILE "$chann:$msg\n";
			close CHAT_FILE;
			
			if ($msg =~ /^\//){
				print $socket "$msg\r\n";
				}else{
				my $to_send = "/privmsg $chann:$msg\r\n";	
				print $socket "$to_send";
				}
				$chat_box-> delete('0.0','end');
				my $filename = "$chann.txt";
			open (READ_CHAT_FILE,$filename) or die "Can't open the logs";
			 local $/;
			$chat_log = <READ_CHAT_FILE>;
			close READ_CHAT_FILE;
			}


			my $display_box = $main->Label(-background => 'white',
				-width => 50,
				-height => 10,
				-justify => 'left',
				-anchor => 'nw',
				-textvariable => \$chat_log,
				-relief =>'sunken')->place(
						-relx => 0.02,
						-rely => 0.10,
						);
		
			
			my $quit_button = $main->Button(-text => 'Quit', 
	      		-command => sub{exit;})->place(
			-anchor => 'se',
			-relx => 1,
			-rely => 0.95);			
			MainLoop();
	  	}
         }
    }
   kill("TERM" => $kidpid);        # send SIGTERM to child
}
else {                             
    # child copies standard input to the socket
    while (defined ($line = <STDIN>)) {
	if ($line eq "/QUIT\n") { print (" Are you sure you want to quit IRC client ? y/n\n");
	$option = <STDIN>;
	if ($option eq "y\n"){
	print "Thank You !! \n";
	kill("TERM" => $kidpid); # send SIGTERM to child			
		}elsif ($option eq "n\n"){
			print "Keep going ...Ignore the error \n";
		}
	}
        print $socket "$line\r\n";
    }	
		
}
exit;


