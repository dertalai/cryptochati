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

__version__ = "0.03"
__author__ = "Dertalai <base64:'ZGVydGFsYWlAZ21haWwuY29t'>"
__copyright__ = \
    "Copyright © 2010 Dertalai <base64:'ZGVydGFsYWlAZ21haWwuY29t'>"

__module_name__ = "Cryptochati"
__module_version__ = __version__
__module_description__ = "Secure and easy chat encryptor"
__module_author__ = __author__

import xchat
import binascii
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
import cPickle
import os
import hashlib
import string


PREFIXES = { # MUST BE 15 CHARS LONG
    "pub": "CryptoChati-PUB", #Public key
    "key": "CryptoChati-KEY", #Encrypted key for next message
    "sig": "CryptoChati-SIG", #Signature of next message
    "enc": "CryptoChati-ENC", #Encrypted text
}

class MsgWrapper:
    ALPHABET = string.digits + string.ascii_letters + string.punctuation
    ALPHABET_LOOKUP = dict((char, i) for (i, char) in enumerate(ALPHABET))
    BASE = len(ALPHABET)
    
    def __init__(self):
        pass
        
    @classmethod
    def wrap(self, type, data, nick):
        # print "wrap:", type, str(data)[:80], nick
        assert PREFIXES.has_key(type)
        
        if type == "pub":
            encodedPub = self.str2baseX(cPickle.dumps(data))
            xchat.get_context().command("raw privmsg " + nick + " " +
                PREFIXES[type] + encodedPub)
                
        elif type == "key":
            encodedKey = self.str2baseX(data)
            xchat.get_context().command("raw privmsg " + nick + " " +
                PREFIXES[type] + encodedKey)
        
        elif type == "sig":
            encodedSig = self.dec2baseX(data)
            xchat.get_context().command("raw privmsg " + nick + " " +
                PREFIXES[type] + encodedSig)
            
        elif type == "enc":
            encodedTxt = self.str2baseX(data)
            xchat.get_context().command("raw privmsg " + nick + " " +
                PREFIXES[type] + encodedTxt)


#    @classmethod
#    def toBase64(self, data):
#        #Quit trailing char (always "\n")
#        return binascii.b2a_base64(data)[:-1]
    
    @classmethod
    def dec2baseX(self, num):
        assert num > 0
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
        num = 0
        for i in string:
            num = num * 256 + ord(i)
        return self.dec2baseX(num)
    
    @classmethod
    def baseX2str(self, data):
        num = self.baseX2dec(data)
        s = ""
        while True:
            num, r = divmod(num, 256)
            s += chr(r)
            if num == 0: break
        return s[::-1]


class Conversations:
    d = dict()
    
    def __init__(self):
        pass
    
    def get(self, nick):
        result = None
        for i in self.d.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                result = self.d.get(i)
        
        if not result:
            self.d[nick] = {
                "publickey": "",
                "txtkey": "",
                "message": "",
                "signature": "",
            }
        
        return self.d.get(nick)
    

class Encryptor:
    #List of friend nicks
    friends = []
    #Public keys dictionary
    keys = {}
    #Sending public key to others
    sendPubKey = True
    #Private and public self keys
    privKey = None
    pubKey = None
    
    conversations = Conversations()
    
    def __init__(self):
        #Decode hooks
        xchat.hook_print("Private Message", self.decode, "Private Message")
        xchat.hook_print("Private Message to Dialog", self.decode, "Private Message to Dialog")
        
        #Generic encode hook
        self.allhook = xchat.hook_command("", self.encode)
        
        #Random generator
        self.randfunc = RandomPool().get_bytes
        
        #Initialize configuration directory
        userDir = os.path.expanduser("~")
        confDir = os.path.join(userDir, ".xchat2/cryptochati.conf")
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



    def cipher(self, string, nick):
        newKey = self.randfunc(32)
        # Don't let key having \0 character
        while "\0" in newKey:
            newKey = self.randfunc(32)
        
        keyText = self.keys[nick].encrypt(newKey, "")[0]
        
        enc = AES.new(newKey)
        #Fill it with null until reaching block size
        newString = string + "\0" * (enc.block_size - (len(string) % enc.block_size))
        newString = enc.encrypt(newString)

        return keyText, newString



    def decipher(self, key, data):
        enc = AES.new(self.privKey.decrypt(key))

        return enc.decrypt(data).replace("\0", "")
        

        
    def sign(self, text):
        hash = hashlib.sha1(text).digest()
        return self.privKey.sign(hash, self.randfunc(16))
        
    def verify(self, text, data, interlocutor):
        pubkey = self.keys[interlocutor.lower()]
        hash = hashlib.sha1(text).digest()
        return pubkey.verify(hash, data)
        

    def openConfiguration(self):
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
                self.privKey = cPickle.load(file)
                print "Private key loaded."
            assert isinstance(self.privKey, RSA.RSAobj_c)
            
        else:
            self.privKey = RSA.generate(512, self.randfunc)
            with open(self.myKeyPath, "wb") as file:
                cPickle.dump(self.privKey, file)
                print "Private key generated and saved in " + self.myKeyPath
        
        if not os.path.isfile(self.keysPath):
            file = open(self.keysPath, "wb")
            cPickle.dump({}, file)
            file.close()
        with open(self.keysPath, "rb") as file:
            self.keys = cPickle.load(file)
            assert isinstance(self.keys, dict)
            print "Friend keys read from " + self.keysPath

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
        
        
        prefix, data = word[1][0:15], word[1][15:]
        conversation = self.conversations.get(interlocutor)
        #Check for a "public key" type message
        if prefix == PREFIXES["pub"]:
            try:
                pubKey = cPickle.loads(MsgWrapper.baseX2str(data))
                assert isinstance(pubKey, RSA.RSAobj_c)
                self.keys[interlocutor.lower()] = pubKey
                file = open(self.keysPath, "wb")
                cPickle.dump(self.keys, file)
                file.close()
                conversation["publickey"] = pubKey
                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst

        elif prefix == PREFIXES["key"]:
            conversation["txtkey"] = MsgWrapper.baseX2str(data)
            return xchat.EAT_XCHAT
            
        elif prefix == PREFIXES["enc"]:
            try:
                decoded = self.decipher(conversation["txtkey"],
                    MsgWrapper.baseX2str(data))
                self.sendPubKey = False
                conversation["message"] = decoded
                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst
                
        elif prefix == PREFIXES["sig"]:
            try:
                indicator = None
                conversation["signature"] = MsgWrapper.baseX2dec(data)
                if self.verify(conversation["message"],
                    (conversation["signature"], ), interlocutor):
                    indicator = "e< "
            except Exception as inst:
                print inst
            if not indicator:
                print "Cryptochati WARNING: Bad signature. " \
                    "Your interlocutor may be an impostor!!"
                indicator = "!!< "
            xchat.emit_print(userdata, indicator + word[0],
                conversation["message"])
            return xchat.EAT_XCHAT
        
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

        prefix = word[0][0:15]
        if prefix in PREFIXES.itervalues():
            #Send text as it comes (formated for a friend)
            return xchat.EAT_NONE
        
        if self.sendPubKey:
            #Send public key, invisible to user (raw)
            MsgWrapper.wrap("pub", self.pubKey, interlocutor)
            
        if self.keys.has_key(interlocutor.lower()):
            text = word_eol[0]
            
            txtSignature = self.sign(text)
            txtKey, encryptedTxt = self.cipher(text, interlocutor.lower())
            #Send key
            MsgWrapper.wrap("key", txtKey, interlocutor)
            #Send real message encrypted raw
            MsgWrapper.wrap("enc", encryptedTxt, interlocutor)
            #Send signature
            MsgWrapper.wrap("sig", txtSignature[0], interlocutor) 
            
            #Show real message unencrypted on chat screen
            xchat.emit_print("Your Message", "e> " + xchat.get_info("nick"),
                text)
            return xchat.EAT_ALL
        else:
            return xchat.EAT_NONE
    


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
