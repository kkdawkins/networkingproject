#!/usr/bin/python

from twisted.internet import reactor, protocol
from twisted.protocols.basic import LineReceiver
import logging
#from datetime import datetime
from time import localtime, strftime

class TriagedMessage():
    def __init__(self, f, t, message):
        self.f = f
        self.t = t
        self.message = message

class IRC(LineReceiver):

    def __init__(self, users, servers, channels, channelNames, messageTriage, contribution_score):
        self.users = users
        self.servers = servers
        self.channels = channels
        self.channelNames = channelNames
        self.messageTriage = messageTriage
        self.contribution_score = contribution_score
        self.myChannels = []
        self.name = None
        self.state = "NEGOTIATE"
        self.serverMessage = "" + strftime("%H:%M:%S", localtime()) + " [Server] " # Global server message, only have to calc once

    def connectionMade(self):
        logger.debug("Connection was made, asking name")
        self.sendLine("004")

    def connectionLost(self, reason):
        if(self.name in self.users):
            for ch in self.myChannels:
                self.channels[ch] = self.channels[ch] - 1
                self.channelNames[ch].remove(self.name)
                if(self.channels[ch] == 0):
                    del self.channels[ch]
                    del self.channelNames[ch]
            self.myChannels = []
            del self.users[self.name]
            logger.debug("Connection was lost with " + self.name)
            announcement = self.serverMessage + self.name + " has quit."
            self.announce(announcement)
        else:
            logger.debug("Connection was lost with unknown")

    def lineReceived(self, line):
        if(self.state == "NEGOTIATE"):
            self.handle_Negotiate(line.rstrip())
        elif(self.state == "GETNAME"):
            self.handle_GETNAME(line.rstrip())
        elif(self.state == "SEARCH"):
            self.handle_SEARCH(line.rstrip())
        else:
            if(self.state == "server" or self.state == "cleared"):
                self.contribution_score = self.contribution_score + 1
            self.handle_CHAT(line.rstrip())

    def handle_SEARCH(self, resp):
        if resp == "yes":
            self.state = "cleared"
            self.contribution_score = self.contribution_score - 1
            self.releaseTriage()
            if self.contribution_score == 50:
                logger.debug("A server's contribution score is at 50. Idling from chat.")
            

    def handle_Negotiate(self, mytype):
        if(mytype == "server"):
            self.state = "server"
            self.name = "server"
            self.servers[self.name] = self
            logger.debug("Server added to chat.")
        elif(mytype == "client"):
            self.state = "GETNAME"
            self.sendLine("[Server] ")
            self.sendLine("Whats your name?")
        else:
            self.sendLine("[server] Unknown identification code.")


    def handle_GETNAME(self, name):
        if name in self.users:
            self.sendLine("Name taken, please choose another.")
            return
        self.sendLine("Welcome, %s!" % (name,))
        self.name = name
        self.users[name] = self
        self.state = "CHAT"
        logger.debug("User " + name + " added to chat.")
        announcement = "[Server] " + name + " has joined."
        self.announce(announcement)

    def handle_CHAT(self, message):
        splitCommand = message.split()
        if len(splitCommand) == 0:
            return
        cmd = self.interpretCommand(splitCommand[0]) # Command is before the first space
        if cmd == 1:
            self.handle_list()
        elif cmd == 2:
            self.handle_help()
        elif cmd == 3 and len(splitCommand) > 1:
            self.handle_join(splitCommand[1])
        elif cmd == 4 and len(splitCommand) > 1:
            self.handle_privMsg(' '.join(splitCommand[1:]))
        elif cmd == 5 and len(splitCommand) > 1:
            self.handle_names(splitCommand[1])
        else:
            self.sendLine("You entered an incorrect/invalid command")
            self.sendLine("Plese refer to /help for avaliable commands")

    def handle_names(self, ch):
        self.sendLine("The following people are in " + ch + ":")
        for name in self.channelNames[ch]:
            self.sendLine(name)

    def handle_privMsg(self, msg):
        msg = msg.split(":")
        if msg[0] in self.myChannels:
            #send the message to that channel
            for name in self.channelNames[msg[0]]:
                proto = self.users[name]
                proto.sendLine(msg[0] + ":" + self.name + ":" + msg[1])
        elif (msg[0] in self.users) or (len(self.servers) > 0):
            logger.debug("Trying to triage message from:" + self.name + " to:" + msg[0] + " msg:" + msg[1])
            self.messageTriage = TriagedMessage(self.name, msg[0], msg[1])
            if len(self.servers) > 0:
                # Ask the servers search:kdawkins
                for name, protocol in self.servers.iteritems():
                    protocol.sendLine("search:"+msg[0])
                    protocol.state = "SEARCH"
                
            elif msg[0] in self.users:
                self.releaseTriage()
            else:
                self.sendLine("Error, user not found.")
                self.messageTriage = None
        else:
            self.sendLine("Target of private message not found.")

    def handle_join(self, ch):
        if ch in self.channels:
            self.myChannels.append(ch)
            self.channels[ch] = self.channels[ch] + 1 # increment the users by one
            self.channelNames[ch].append(self.name) # shouldnt need to append since a list is initialized on creation
        else: # if it is in self.channels, it is in self.channelNames ... lol :-)
            self.channels[ch] = 1
            self.myChannels.append(ch)
            self.channelNames[ch] = list()
            self.channelNames[ch].append(self.name)

        self.sendLine(ch + ":Welcome to the channel " + ch)
        self.sendLine(ch + ":There are also " + str(self.channels[ch] - 1) + " other users here") # -1 because we dont want to count ourself!


    def handle_list(self):
        self.sendLine("Displaying currently created channels")
        self.sendLine("use /join <channel> to join one or create your own!")
        for ch in self.channels:
            self.sendLine(ch + " " + str(self.channels[ch]) + " users")

    def handle_help(self):
        self.sendLine("Displaying help for CS525 IRC")
        self.sendLine("Command                      Result")
        self.sendLine("/help                        Shows avaliable commands")
        self.sendLine("/list                        Lists avaliable channels")
        self.sendLine("/join <channel>              Joins (or creates) channel")
        self.sendLine("/names <channel>             Returns who is in the channel")
        self.sendLine("/privmsg <channel>:msg       Sends a message to a user or channel")

    def distrubute(self, message):
        toSend = "%s <%s> %s" % (strftime("%H:%M:%S", localtime()), self.name, message)
        for name, protocol in self.users.iteritems():
            if protocol != self:
                protocol.sendLine(toSend)

    def announce(self, message):
        for name, protocol in self.users.iteritems():
            if protocol != self:
                protocol.sendLine(message)

    def interpretCommand(self, command):
        command = command.lower()
        if command == "/list":
            return 1
        elif command == "/help":
            return 2
        elif command == "/join":
            return 3
        elif command == "/privmsg":
            return 4
        elif command == "/names":
            return 5
        else:
            return -1

    def releaseTriage(self):
        for user, triage in self.users.iteritems():
            if triage.messageTriage != None:
                for name,protocol in self.servers.iteritems():
                    if protocol.state == "cleared" and protocol.contribution_score > 50: 
                        protocol.state = "server"
                        protocol.sendLine("From: " + triage.messageTriage.f + " To:" + triage.messageTriage.t + " ->" + triage.messageTriage.message)
                if(str(triage.messageTriage.t) in self.users):
                    proto = self.users[str(triage.messageTriage.t)]
                    proto.sendLine("[" + triage.messageTriage.f + "] " + triage.messageTriage.message)
                triage.messageTriage = None # clear the triage



class IRCFactory(protocol.Factory):
    def __init__(self):
        self.users = {}
        self.servers = {}
        self.channels = {}
        self.channelNames = {}
        self.messageTriage = None
        self.contribution_score = 100

    def buildProtocol(self, addr):
        return IRC(self.users, self.servers, self.channels, self.channelNames, self.messageTriage, self.contribution_score)


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("./server.log")
logger.addHandler(fh)

logger.debug("Server Started at " + strftime("%H:%M:%S", localtime()))



reactor.listenTCP(5000, IRCFactory())
reactor.run()


