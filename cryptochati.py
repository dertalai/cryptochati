#!/usr/bin/python
# -*- coding: UTF-8 -*-

############################################################################
##                                                                        ##
## Cryptochati XChat-plugin                                               ##
##                                                                        ##
## Copyright (C) 2010 Dertalai <base64:'ZGVydGFsYWlAZ21haWwuY29t'>        ##
##                                                                        ##
## This program is free software: you can redistribute it and/or modify   ##
## it under the terms of the GNU General Public License as published by   ##
## the Free Software Foundation, either version 3 of the License, or      ##
## (at your option) any later version.                                    ##
##                                                                        ##
## This program is distributed in the hope that it will be useful,        ##
## but WITHOUT ANY WARRANTY; without even the implied warranty of         ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          ##
## GNU General Public License for more details.                           ##
##                                                                        ##
## You should have received a copy of the GNU General Public License      ##
## along with this program.  If not, see <http://www.gnu.org/licenses/>.  ##
##                                                                        ##
############################################################################

"""Cryptochati XChat-plugin
Read README file for features, installation and use of this plugin.
"""

__version__ = "0.045"
__author__ = "Dertalai <base64:'ZGVydGFsYWlAZ21haWwuY29t'>"
__copyright__ = \
    "Copyright © 2010-2014 Dertalai <base64:'ZGVydGFsYWlAZ21haWwuY29t'>"

__module_name__ = "Cryptochati"
__module_version__ = __version__
__module_description__ = "Secure and easy chat encryptor"
__module_author__ = __author__

import xchat
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
try:
    from Crypto.Random import get_random_bytes
except ImportError:
    try:
        from os import urandom as get_random_bytes
    except ImportError:
        get_random_bytes = open("/dev/urandom", "rb").read

import pickle
import os
import hashlib
import string


PREFIXES = {  # VALUES MUST BE OF SAME SIZE
    "pub": "CryptoChati-PUB",  # Public key
    "key": "CryptoChati-KEY",  # Encrypted key for next message
    "sig": "CryptoChati-SIG",  # Signature of next message
    "enc": "CryptoChati-ENC",  # Encrypted text
    "mul": "CryptoChati-MUL",  # Multipart encapsulator
}
PREFIXSIZE = len(PREFIXES["pub"])

class MsgWrapper:
    # Base94
    ALPHABET = string.digits + string.ascii_letters + string.punctuation
    ALPHABET_LOOKUP = dict((char, i) for (i, char) in enumerate(ALPHABET))
    BASE = len(ALPHABET)
    CHARSIZE = 256

    @classmethod
    def wrap(self, datatype, data, nick):
        #print "wrap:", type, str(data)[:80], nick
        SIZE = 384  # Max size allowed for one part
        assert PREFIXES.has_key(datatype)

        if datatype == "pub":
            encoded = self.str2baseX(data.exportKey())
        elif datatype == "key":
            encoded = self.str2baseX(data)

        elif datatype == "sig":
            encoded = self.dec2baseX(data)

        elif datatype == "enc":
            encoded = self.str2baseX(data)

        elif datatype == "mul":
            encoded = data

        if len(encoded) > SIZE:
            #Sends recursively parts in this order: N, N-1, ..., 1
            MsgWrapper.wrap("mul", encoded[SIZE:], nick)
            envio = PREFIXES[datatype] + encoded[:SIZE]
            xchat.get_context().command("raw privmsg " + nick + " " + envio)
        else:
            envio = PREFIXES[datatype] + encoded
            xchat.get_context().command("raw privmsg " + nick + " " + envio)

    @classmethod
    def unwrap(self, data):
        # Get datatype
        datatype = None
        prefix = data[:PREFIXSIZE]
        for i in PREFIXES.iterkeys():
            if PREFIXES[i] == prefix:
                datatype = i
                break

        decoded = None
        encoded = data[PREFIXSIZE:]
        if datatype == "pub":
            decoded = RSA.importKey(self.baseX2str(encoded))
        elif datatype == "key":
            decoded = self.baseX2str(encoded)
        elif datatype == "sig":
            decoded = self.baseX2dec(encoded)
        elif datatype == "enc":
            decoded = self.baseX2str(encoded)
        elif datatype == "mul":
            decoded = encoded

        return datatype, decoded


    @classmethod
    def dec2baseX(self, num):
        assert num >= 0
        s = []
        while True:
            num, r = divmod(num, self.BASE)
            s.append(self.ALPHABET[r])
            if num == 0: break
        return ''.join(reversed(s))

    @classmethod
    def baseX2dec(self, data):
        num = 0
        for c in data:
            num = num * self.BASE + self.ALPHABET_LOOKUP[c]
        return num

    @classmethod
    def str2baseX(self, string):
        #avoid ignoring leading \x00 characters
        string = "\x01" + string
        num = 0
        for i in string:
            num = num * self.CHARSIZE + ord(i)
        return self.dec2baseX(num)

    @classmethod
    def baseX2str(self, data):
        num = self.baseX2dec(data)
        s = ""
        while True:
            num, r = divmod(num, self.CHARSIZE)
            s += chr(r)
            if num == 0: break
        #reverse and remove leading \x01
        return s[-2::-1]


class Conversations(dict):
    def get(self, nick):
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                nick = i

        if not self.has_key(nick):
            super(Conversations, self).__setitem__(nick, {
                #RSA public key of this interlocutor currently in use
                "publickey": None,
                #AES object for incoming messages
                "txtkey": None,
                #key + initial IV pair of incoming messages
                "keyiv": None,
                #signature of initial incoming message
                "signature": None,
                #AES object for outcoming messages
                "sndtxtkey": None,
                #boolean: we need to send our public key to this interlocutor
                "sndpublickey": True,
                #buffer for multipart incoming message
                "multipart": "",
            })

        return super(Conversations, self).get(nick)

    def reset(self, nick):
        conversation = self.get(nick)
        conversation["txtkey"] = None
        conversation["keyiv"] = None
        conversation["sndpublickey"] = True
        conversation["sndtxtkey"] = None
        conversation["multipart"] = ""



class Keys(dict):
    def get(self, nick):
        result = nick
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = i
        return super(Keys, self).get(result)

    def __getitem__(self, nick):
        result = nick
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = i
        return super(Keys, self).__getitem__(result)

    def __setitem__(self, nick, x):
        result = nick
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = i
        return super(Keys, self).__setitem__(result, x)

    def has_key(self, nick):
        result = nick
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = i
        return super(Keys, self).has_key(result)

    def pop(self, nick, value):
        result = nick
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = i
        return super(Keys, self).pop(result, value)

class Encryptor:
    #List of friend nicks
    friends = []
    #Public keys dictionary
    keys = Keys()
    #Private and public self keys
    privKey = None
    pubKey = None
    #Conversation dicts
    conversations = Conversations()

    KEY_SYMBOL = '\xe2\x9a\xb7 '

    def __init__(self):
        #Decode hooks
        xchat.hook_print("Private Message", self.decode, "Private Message")
        xchat.hook_print("Private Message to Dialog", self.decode, "Private Message to Dialog")

        xchat.hook_print("Quit", self.quithook, "Quit")
        xchat.hook_print("Connected", self.resetconversationshook, "Connected")
        xchat.hook_print("Your Nick Changing", self.resetconversationshook,
            "Your Nick Changing")

        #Generic encode hook
        self.allhook = xchat.hook_command("", self.encode)

        #TODO RandomPool is know to be broken
        #Random generator
        self.randfunc = get_random_bytes

        #Initialize configuration directory
        confDir = xchat.get_info("xchatdirfs") + "/cryptochati.conf"
        if not os.path.isdir(confDir):
            os.makedirs(confDir, 0700)

        #Friends file
        self.friendsPath = os.path.join(confDir, "friends.txt")
        #Private key file
        self.myKeyPath = os.path.join(confDir, "my.key")
        #Friends' public keys file
        self.keysPath = os.path.join(confDir, "public.keys")

        #Create/load configuration
        self.openConfiguration()

        #Friend management hook
        xchat.hook_command("Friend", self.friendhook, "Friend", help=
"""Usage:
FRIEND ADD <nick> - adds <nick> as a trusted friend
FRIEND DEL <nick> - deletes <nick> from trusted friends
FRIEND LIST - lists current trusted friends""")



    def quithook(self, word, word_eol, userdata):
        #print "quithook:", word[0]
        nick = word[0]

        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(nick, friend) == 0:
                sigue = True
                break
        if sigue:
            #Reset the quitting-friend conversation
            self.conversations.reset(nick)

        return xchat.EAT_NONE

    def resetconversationshook(self, word, word_eol, userdata):
        #print "resetconversationshook: ", word
        #Reset all conversations
        self.conversations = Conversations()

        return xchat.EAT_NONE

    def friendhook(self, word, word_eol, userdata):
        if len(word) < 2:
            xchat.command("help friend")
        else:
            command = word[1].lower()
            if command == "list":
                print self.friends
            elif command == "add" and len(word) == 3:
                addnick = word[2]
                found = False
                for nick in self.friends:
                    if xchat.nickcmp(nick, addnick) == 0:
                        found = True
                        print "Nick was already added as " + nick
                        break

                if not found:
                    self.friends.append(addnick)
                    self.savefriends()
                    print addnick + " has been added as a friend"

            elif (command == "del" or command == "delete") and len(word) == 3:
                delnick = word[2]
                found = False
                for nick in self.friends:
                    if xchat.nickcmp(nick, delnick) == 0:
                        found = nick
                        break

                if found:
                    self.friends.remove(found)
                    self.savefriends()
                    #delete stored public key
                    self.conversations.get(found)["publickey"] = None
                    self.keys.pop(found, None)
                    self.savekeys()

                    print found + " has been deleted from friends list"
                else:
                    print delnick + " was not on friends list"

            else:
                xchat.command("help friend")

        return xchat.EAT_XCHAT


    def savefriends(self):
        with open(self.friendsPath, "wb") as file:
            for i in self.friends:
                file.writelines(i + "\n")

    def savekeys(self):
        with open(self.keysPath, "wb") as file:
            pickle.dump(self.keys, file)
            file.close()


    def cipher(self, string, nick):
        conversation = self.conversations.get(nick)

        keyText = None
        if conversation["sndtxtkey"] == None:
            newKey = self.randfunc(32)
            iv = self.randfunc(16)
            conversation["sndtxtkey"] = AES.new(newKey, AES.MODE_CBC, iv)
            keyText = newKey + iv
        enc = conversation["sndtxtkey"]

        #Fill it with null until reaching block size
        newString = string + "\0" * (enc.block_size - (len(string) % enc.block_size))
        newString = enc.encrypt(newString)

        #Update key chaining
        conversation["sndtxtkey"] = enc

        return keyText, newString



    def decipher(self, key, data):
        return key.decrypt(data).replace("\0", "")



    def sign(self, text):
        hash = hashlib.sha1(text).digest()
        return self.privKey.sign(hash, self.randfunc(16))

    def verify(self, text, data, interlocutor):
        pubkey = self.keys[interlocutor]
        hash = hashlib.sha1(text).digest()
        return pubkey.verify(hash, data)


    def openConfiguration(self):
        PUBKEYSIZE = 2048
        if not os.path.isfile(self.friendsPath):
            open(self.friendsPath, "wb").close()
        with open(self.friendsPath, "rb") as file:
            for line in file.readlines():
                nick = line.strip()
                if nick != "":
                    self.friends.append(nick)
        print "friends: ", self.friends

        if os.path.isfile(self.myKeyPath):
            with open(self.myKeyPath, "rb") as file:
                self.privKey = RSA.importKey(file.read())
                print "Private key loaded from " + self.myKeyPath
            # assert isinstance(self.privKey, RSA.RSAobj_c)

        else:
            self.privKey = RSA.generate(PUBKEYSIZE, self.randfunc)
            with open(self.myKeyPath, "wb") as file:
                file.write(self.privKey.exportKey())
                print "Private key generated and saved in " + self.myKeyPath

        if os.path.isfile(self.keysPath):
            with open(self.keysPath, "rb") as file:
                self.keys = pickle.load(file)
            assert isinstance(self.keys, Keys)
            print "Friend keys loaded from " + self.keysPath
        else:
            self.keys = Keys()
            self.savekeys()
            assert os.path.isfile(self.keysPath)
            print "Empty friend keys generated and saved in " + self.keysPath

        self.pubKey = self.privKey.publickey()

    def decode(self, word, word_eol, userdata):
        #print "decode", word, word_eol, userdata
        interlocutor = xchat.get_info("channel")

        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(interlocutor, friend) == 0:
                sigue = True
                break
        if not sigue:
            #Take as it comes (from no-friend)
            return xchat.EAT_NONE

        conversation = self.conversations.get(interlocutor)
        datatype, data = MsgWrapper.unwrap(word_eol[1] + conversation["multipart"])

        #First, check for a multipart message
        if datatype == "mul":
            conversation["multipart"] = data
            #print "mul:", conversation["multipart"]
            return xchat.EAT_XCHAT
        else:
            conversation["multipart"] = ""

        #Check for a "public key" type message
        if datatype == "pub":
            try:
                pubKey = data
                # print pubKey
                assert isinstance(pubKey, RSA._RSAobj)
                possibleimpostor = False
                #Caution: negative comparation "!=" doesn't work for RSA
                #objects. It's always True, so you must use "not ==" instead.
                if self.keys.has_key(interlocutor) and \
                    not self.keys.get(interlocutor) == pubKey:
                    possibleimpostor = True
                    self.warn("Your interlocutor's public key has changed. "
                        "She may be an impostor!! If you are sure she isn't, "
                        "use \"/FRIEND DEL <nick>\" and then \"/FRIEND ADD "
                        "<nick>\" commands to restore trusting. Otherwise, "
                        "you'll keep receiving warning messages.")
                if not possibleimpostor:
                    self.keys[interlocutor] = pubKey
                    self.savekeys()
                conversation["publickey"] = pubKey
                self.conversations.reset(interlocutor)

                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst

        elif datatype == "key":
            decoded = self.privKey.decrypt(data)
            key, iv = decoded[:32], decoded[32:]
            conversation["txtkey"] = AES.new(key, AES.MODE_CBC, iv)
            conversation["keyiv"] = decoded

            return xchat.EAT_XCHAT

        elif datatype == "sig":
            try:
                verified = False
                conversation["signature"] = (data, )
                if self.verify(conversation["keyiv"], conversation["signature"],
                        interlocutor):
                    verified = True
            except Exception as inst:
                self.conversations.reset(interlocutor)
                print inst
            if verified:
                conversation["signature"] = None
                conversation["keyiv"] = None
            else:
                self.warn("Bad signature. " \
                    "Your interlocutor may be an impostor!!")

            return xchat.EAT_XCHAT

        elif datatype == "enc":
            try:
                if conversation["txtkey"] == None:
                    exceptionmsg = "It's not possible to decrypt " \
                        "your interlocutor's message. She's using unkown conversation key. Send her a message to resynchronize."
                    self.warn(exceptionmsg)
                    raise Exception(exceptionmsg)
                decoded = self.decipher(conversation["txtkey"], data)
                xchat.emit_print(userdata, self.KEY_SYMBOL + word[0], decoded)
                # Decrypted correctly, so the interlocutor already has your pubkey
                conversation["sndpublickey"] = False

                return xchat.EAT_XCHAT
            except Exception as inst:
                self.conversations.reset(interlocutor)
                print inst

        return xchat.EAT_NONE


    def encode(self, word, word_eol, userdata):
        #print "encode", word, word_eol
        interlocutor = xchat.get_context().get_info("channel")
        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(interlocutor, friend) == 0:
                sigue = True
        if not sigue:
            #Send text as it comes (unencrypted to a no-friend)
            return xchat.EAT_NONE

        prefix = word_eol[0][0:PREFIXSIZE]
        conversation = self.conversations.get(interlocutor)
        if prefix in PREFIXES.itervalues():
            #Send text as it comes (formated for a friend)
            return xchat.EAT_NONE

        if conversation["sndpublickey"]:
            #Send public key, invisible to user (raw)
            MsgWrapper.wrap("pub", self.pubKey, interlocutor)
            conversation["sndpublickey"] = False

        if self.keys.has_key(interlocutor):
            text = word_eol[0]

            txtKey, encryptedTxt = self.cipher(text, interlocutor)
            if txtKey is not None:
                txtSignature = self.sign(txtKey)
                #Send key
                pubkey = None
                if conversation["publickey"] is not None:
                    pubkey = conversation["publickey"]
                else:
                    pubkey = self.keys[interlocutor]
                MsgWrapper.wrap("key", pubkey.encrypt(txtKey, "")[0],
                    interlocutor)
                #Send signature
                MsgWrapper.wrap("sig", txtSignature[0], interlocutor)

            #Send real message encrypted raw
            MsgWrapper.wrap("enc", encryptedTxt, interlocutor)

            #Show real message unencrypted on chat screen
            xchat.emit_print("Your Message", self.KEY_SYMBOL +
                xchat.get_info("nick"), text)
            return xchat.EAT_ALL
        else:
            return xchat.EAT_NONE

    def warn(self, msg):
        xchat.emit_print("Private Message to Dialog", "5,17Cryptochati",
            "" + msg)
        return



#Main
e = Encryptor()
print "Loaded plugin:", __module_name__, __module_version__



#EVENTS = [
#  ("Channel Action", 1),
#  ("Channel Action Hilight", 1),
#  ("Channel Message", 1),
#  ("Channel Msg Hilight", 1),
#  ("Channel Notice", 2),
#  ("Generic Message", (0, 1)),
#  ("Kick", 3),
#  ("Killed", 1),
#  ("Motd", 0),
#  ("Notice", 1),
#  ("Part with Reason", 3),
#  ("Private Message", 1),
#  ("Private Message to Dialog", 1),
#  ("Quit", 1),
#  ("Receive Wallops", 1),
#  ("Server Notice", 0),
#  ("Server Text", 0),
#  ("Topic", 1),
#  ("Topic Change", 1),
#]
