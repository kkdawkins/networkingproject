#!/usr/bin/python

from twisted.internet import reactor, protocol
from twisted.protocols.basic import LineReceiver
import logging
#from datetime import datetime
from time import localtime, strftime

class IRC(LineReceiver):

    CMD_HELP = 1
    CMD_LIST = 2
    CMD_ERR = -1

    def __init__(self, users):
        self.users = users
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
        cmd = self.interpretCommand(message.split()[0]) # Command is before the first space
        if cmd == CMD_HELP:
            handle_help(self)

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

    def interpretCommand(command):
        command = command.lower()
        if command == "/list":
            return CMD_LIST
        elif command == "/help":
            return CMD_HELP
        else:
            return CMD_ERR;

class IRCFactory(protocol.Factory):
    def __init__(self):
        self.users = {}
    
    def buildProtocol(self, addr):
        return IRC(self.users)


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("./server.log")
logger.addHandler(fh)

logger.debug("Server Started at " + strftime("%H:%M:%S", localtime()))



reactor.listenTCP(5000, IRCFactory())
reactor.run()


