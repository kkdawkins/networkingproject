#!/usr/bin/python

from twisted.internet import reactor, protocol
from twisted.protocols.basic import LineReceiver
import logging
from datetime import datetime

class IRC(LineReceiver):
    def __init__(self, users):
        self.users = users
        self.name = None
        self.state = "GETNAME"

    def connectionMade(self):
        logger.debug("Connection was made, asking name")
        self.sendLine("004")
        self.sendLine("Whats your name?")

    def connectionLost(self,reason):
        if(self.name in self.users):
            del self.users[self.name]
            logger.debug("Connection was lost with " + self.name)
            announcement = "[Server] " + self.name + " has quit."
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
        announcement = "[Server] " + name + " has joined."
        self.announce(announcement)

    def handle_CHAT(self, message):
        toSend = "<%s> %s" % (self.name, message)
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


