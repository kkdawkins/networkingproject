#!/usr/bin/python

from twisted.internet import reactor, protocol
from twisted.protocols.basic import LineReceiver
import logging
#from datetime import datetime
from time import gmtime, strftime

class IRC(LineReceiver):
    def __init__(self, users):
        self.users = users
        self.name = None
        self.state = "GETNAME"
        self.serverMessage = strftime("%H:%M:%S", gmtime()) + " [Server] " # Global server message, only have to calc once

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
            self.handle_GETNAME(line)
        else:
            self.handle_CHAT(line)

    def handle_GETNAME(self, name):
        if name in self.users:
            self.sendLine("Name taken, please choose another.")
            return
        self.sendLine("Welcome, %s!" % (name,))
        self.name = name
        self.users[name] = self
        self.state = "CHAT"
        logger.debug("User " + name + " added to chat.")
        announcement = self.serverMessage + name + " has joined."
        self.announce(announcement)

    def handle_CHAT(self, message):
        toSend = "%s <%s> %s" % (strftime("%H:%M:%S", gmtime()), self.name, message)
        for name, protocol in self.users.iteritems():
            if protocol != self:
                protocol.sendLine(toSend)

    def announce(self, message):
        for name, protocol in self.users.iteritems():
            if protocol != self:
                protocol.sendLine(message)

class IRCFactory(protocol.Factory):
    def __init__(self):
        self.users = {}
    
    def buildProtocol(self, addr):
        return IRC(self.users)


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("./server.log")
logger.addHandler(fh)

logger.debug("Server Started at " + datetime.now().isoformat())



reactor.listenTCP(5000, IRCFactory())
reactor.run()


