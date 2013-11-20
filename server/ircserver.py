#!/usr/bin/python

from twisted.internet import reactor, protocol
from twisted.protocols.basic import LineReceiver
import logging
#from datetime import datetime
from time import localtime, strftime

class IRC(LineReceiver):

    def __init__(self, users, channels):
        self.users = users
        self.channels = channels
        self.myChannels = []
        self.name = None
        self.state = "GETNAME"
        self.serverMessage = "" + strftime("%H:%M:%S", localtime()) + " [Server] " # Global server message, only have to calc once

    def connectionMade(self):
        logger.debug("Connection was made, asking name")
        self.sendLine("004")
        self.sendLine("[Server] ")
        self.sendLine("Whats your name?")

    def connectionLost(self,reason):
        if(self.name in self.users):
            for ch in myChannels:
                self.channels[ch] = self.channels[ch] - 1
                if(self.channels[ch] == 0):
                    del self.channels[ch]
            self.myChannels = []
            del self.users[self.name]
            logger.debug("Connection was lost with " + self.name)
            announcement = self.serverMessage + self.name + " has quit."
            self.announce(announcement)
        else:
            logger.debug("Connection was lost with uknown")

    def lineReceived(self, line):
        if(self.state == "GETNAME"):
            self.handle_GETNAME(line.rstrip())
        else:
            self.handle_CHAT(line.rstrip())

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
        cmd = self.interpretCommand(splitCommand[0]) # Command is before the first space
        if cmd == 1:
            self.handle_list()
        elif cmd == 2:
            self.handle_help()
        elif cmd == 3:
            self.handle_join(splitCommand[1])

    def handle_join(self, ch):
        if ch in self.channels:
            self.myChannels.append(ch)
            self.channels[ch] = self.channels[ch] + 1 # increment the users by one
        else:
            self.channels[ch] = 1
            self.myChannels.append(ch)

        self.sendLine(ch + ":Welcome to the channel " + ch)
        self.sendLine(ch + ":There are also " + str(self.channels[ch] - 1) + " other users here") # -1 because we dont want to count ourself!


    def handle_list(self):
        self.sendLine("Displaying currently created channels")
        self.sendLine("use /join <channel> to join one or create your own!")
        for ch in self.channels:
            self.sendLine(ch + " " + str(self.channels[ch]) + " users")

    def handle_help(self):
        self.sendLine("Displaying help for CS525 IRC")
        self.sendLine("Command                   Result")
        self.sendLine("/help                     Shows avaliable commands")
        self.sendLine("/list                     Lists avaliable channels")

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
        else:
            return -1

class IRCFactory(protocol.Factory):
    def __init__(self):
        self.users = {}
        self.channels = {}
    
    def buildProtocol(self, addr):
        return IRC(self.users, self.channels)


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("./server.log")
logger.addHandler(fh)

logger.debug("Server Started at " + strftime("%H:%M:%S", localtime()))



reactor.listenTCP(5000, IRCFactory())
reactor.run()


