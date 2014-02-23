#!/usr/bin/env python
"""A simple autonomous Twitch.TV IRC client

To instruct this client to connect as <username> with OAuth password <password>
before joining channel <channel> and listening for commands from <trustedNick>,
use the following command line parameters:

  ./twitchtvircclient.py --trustedNick "<trustedNick>" "<username>" "<password>" "<channel>"

Although this client is incomplete, it demonstrates a simple technique for
parsing a handful of common Twitch.TV IRC commands. Additionally, it provides
a simple "!echo <message>" command that will echo back a message from a trusted
user based on his or her IRC nick.

This code is far from clean and has only been lightly tested. Because I threw
this together as a quick demonstration, the existing implementation might mis-
interpret one or more messages produced by Twitch.TV IRC servers.

Unfortunately, the only documentation I could find for the Twitch.TV IRC server
implementation[1] was somewhat terse on certain implementation details, such as
how to determine when authentication information is invalid. I experimented
once or twice and concluded (for this demo) that receiving a NOTICE message
before "common" messages with IDs 1-4 was sufficient for me to assume that
the authentication information was invalid. I could be wrong. :)

[1]: <http://help.twitch.tv/customer/portal/articles/1302780-twitch-irc>"""
from __future__ import print_function
import argparse, re, signal, socket, sys, time

RECEIVE_BUFFER_LENGTH = 4096

TWITCHTV_IRC_HOST = "irc.twitch.tv"
TWITCHTV_IRC_PORT = 6667

TWITCHTV_IRC_ID_FORMAT = r"[-_a-zA-Z0-9]+"
TWITCHTV_IRC_HOST_FORMAT = r"(?P<Host>[-a-zA-Z0-9]+(?:\.[-a-zA-Z0-9]+)*)"
TWITCHTV_IRC_NICK_FORMAT = r"(?P<Nick>{0})".format(TWITCHTV_IRC_ID_FORMAT)
TWITCHTV_IRC_NAME_FORMAT = r"(?P<Name>{0})".format(TWITCHTV_IRC_ID_FORMAT)
TWITCHTV_IRC_USER_FORMAT = r"(?P<User>{0}(?:!{1}@{2})?)".format(TWITCHTV_IRC_NICK_FORMAT, TWITCHTV_IRC_NAME_FORMAT, TWITCHTV_IRC_HOST_FORMAT)
TWITCHTV_IRC_CHANNEL_FORMAT = r"(?P<Channel>#{0})".format(TWITCHTV_IRC_ID_FORMAT)

TWITCHTV_IRC_COMMON_MESSAGE_RE = re.compile(r":{0} (?P<MessageId>[0-9]+) {1} :?(?P<Message>.+)".format(TWITCHTV_IRC_HOST_FORMAT, TWITCHTV_IRC_NICK_FORMAT))
TWITCHTV_IRC_PRIVMSG_MESSAGE_RE = re.compile(r":{0} PRIVMSG (?P<Target>[-_#a-zA-Z0-9]+) :(?P<Message>.*)".format(TWITCHTV_IRC_USER_FORMAT))
TWITCHTV_IRC_MODE_MESSAGE_RE = re.compile(r":{0} MODE {1} (?P<Mode>[-+][a-zA-Z]+) {2}".format(TWITCHTV_IRC_HOST_FORMAT, TWITCHTV_IRC_CHANNEL_FORMAT, TWITCHTV_IRC_NICK_FORMAT))
TWITCHTV_IRC_JOIN_MESSAGE_RE = re.compile(r":{0} JOIN {1}".format(TWITCHTV_IRC_USER_FORMAT, TWITCHTV_IRC_CHANNEL_FORMAT))
TWITCHTV_IRC_PART_MESSAGE_RE = re.compile(r":{0} PART {1}".format(TWITCHTV_IRC_USER_FORMAT, TWITCHTV_IRC_CHANNEL_FORMAT))
TWITCHTV_IRC_NOTICE_MESSAGE_RE = re.compile(r":{0} NOTICE * :(?P<Message>.+)".format(TWITCHTV_IRC_HOST_FORMAT))
TWITCHTV_IRC_PING_MESSAGE_RE = re.compile(r"PING {0}".format(TWITCHTV_IRC_HOST_FORMAT))

TWITCHTV_IRC_INITIAL_MESSAGE_ID_LIST = [1, 2, 3, 4]

def send(clientSocket, message):
    if len(message) > 0:
        clientSocket.sendall(message + "\n")
        print(message)

def receive(clientSocket, responseHandler):
    state = None

    response = clientSocket.recv(RECEIVE_BUFFER_LENGTH)
    if response:
        for responseLine in response.split("\n"):
            if len(responseLine) == 0:
                continue
            parsedResponse = parseResponse(responseLine)
            state = responseHandler(parsedResponse, state)

    return state

def close(clientSocket):
    send(clientSocket, "QUIT")
    clientSocket.shutdown(socket.SHUT_RDWR)
    print("Closed socket")

def privmsg(clientSocket, target, message):
    send(clientSocket, "PRIVMSG {0} :{1}".format(target, message))

def parseResponse(response):
    parsedResponse = TWITCHTV_IRC_COMMON_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "common",
            "host": parsedResponse.group("Host"),
            "messageId": int(parsedResponse.group("MessageId")),
            "nick": parsedResponse.group("Nick"),
            "message": parsedResponse.group("Message")
        }

    parsedResponse = TWITCHTV_IRC_PRIVMSG_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "privmsg",
            "user": parsedResponse.group("User"),
            "nick": parsedResponse.group("Nick"),
            "name": parsedResponse.group("Name"),
            "host": parsedResponse.group("Host"),
            "target": parsedResponse.group("Target"),
            "message": parsedResponse.group("Message")
        }

    parsedResponse = TWITCHTV_IRC_MODE_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "mode",
            "host": parsedResponse.group("Host"),
            "channel": parsedResponse.group("Channel"),
            "mode": parsedResponse.group("Mode"),
            "nick": parsedResponse.group("Nick")
        }

    parsedResponse = TWITCHTV_IRC_JOIN_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "join",
            "user": parsedResponse.group("User"),
            "nick": parsedResponse.group("Nick"),
            "name": parsedResponse.group("Name"),
            "host": parsedResponse.group("Host"),
            "channel": parsedResponse.group("Channel")
        }

    parsedResponse = TWITCHTV_IRC_PART_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "part",
            "user": parsedResponse.group("User"),
            "nick": parsedResponse.group("Nick"),
            "name": parsedResponse.group("Name"),
            "host": parsedResponse.group("Host"),
            "channel": parsedResponse.group("Channel")
        }

    parsedResponse = TWITCHTV_IRC_NOTICE_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "notice",
            "host": parsedResponse.group("Host"),
            "nick": parsedResponse.group("Nick"),
            "message": parsedResponse.group("Message")
        }

    parsedResponse = TWITCHTV_IRC_PING_MESSAGE_RE.match(response)
    if parsedResponse:
        return {
            "type": "ping",
            "host": parsedResponse.group("Host")
        }

    return {
        "type": "other",
        "message": response
    }

def interruptSignalHandler(signal, frame):
    print("Exiting due to a keyboard interrupt request")

    global clientSocket
    if clientSocket:
        close(clientSocket)
        clientSocket = None

if __name__ == "__main__":
    argumentParser = argparse.ArgumentParser(description="A simple autonomous Twitch.TV IRC client")
    argumentParser.add_argument("username", help="The Twitch.TV username used by the client during authentication")
    argumentParser.add_argument("password", help="The Twitch.TV OAuth password used by the client during authentication (excluding \"oauth:\")")
    argumentParser.add_argument("channel", help="The channel joined after authentication")
    argumentParser.add_argument("--trustedNick", help="An optional \"trusted\" IRC nick that may trigger autonomous commands")

    argumentList = argumentParser.parse_args()

    signal.signal(signal.SIGINT, interruptSignalHandler)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((TWITCHTV_IRC_HOST, TWITCHTV_IRC_PORT))
    send(clientSocket, "PASS oauth:" + argumentList.password)
    send(clientSocket, "NICK " + argumentList.username)

    authenticated = False
    expectedMessageIdList = TWITCHTV_IRC_INITIAL_MESSAGE_ID_LIST

    def unauthenticatedResponseHandler(response, state):
        global authenticated, expectedMessageIdList
        if response["type"] == "notice":
            raise StandardError(response["message"])
        elif response["type"] == "common" and response["messageId"] in expectedMessageIdList:
            expectedMessageIdList.remove(response["messageId"])
            authenticated = len(expectedMessageIdList) > 0

    while not authenticated:
        try:
            receive(clientSocket, unauthenticatedResponseHandler)
        except (StandardError, socket.error) as e:
            print("error: {0}".format(e), file=sys.stderr)
            break

        time.sleep(0.25)

    if not authenticated:
        print("error: unable to authenticate", file=sys.stderr)
        close(clientSocket)
        sys.exit(1)

    send(clientSocket, "JOIN " + argumentList.channel)

    trustedNickList = [argumentList.username]
    if argumentList.trustedNick:
        trustedNickList.append(argumentList.trustedNick)

    def messageResponseHandler(response):
        if response["nick"] not in trustedNickList:
            return

        match = re.match(r"!echo (?P<Message>.+)", response["message"])
        if match:
            privmsg(clientSocket, response["target"], match.group("Message"))

    def authenticatedResponseHandler(response, state):
        if response["type"] == "common":
            print("[{0}/{1:03}] {2}".format(response["type"], response["messageId"], response["message"]))
        elif response["type"] == "privmsg":
            print("[{0}/{1}] <{2}> {3}".format(response["type"], response["target"], response["nick"], response["message"]))
            messageResponseHandler(response)
        elif response["type"] == "join":
            print("[{0}/{1}] <{2}> joined".format(response["type"], response["channel"], response["nick"]))
        elif response["type"] == "part":
            print("[{0}/{1}] <{2}> parted".format(response["type"], response["channel"], response["nick"]))
        elif response["type"] == "ping":
            send(clientSocket, "PONG")
        else:
            print("[{0}]: {1}".format(response["type"], response))        

    while clientSocket:
        try:
            receive(clientSocket, authenticatedResponseHandler)
        except socket.error as e:
            print("error: {0}".format(e), file=sys.stderr)
            break

    if clientSocket:
        close(clientSocket)
