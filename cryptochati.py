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
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
import cPickle
import os
import hashlib
import string


PREFIXES = { # VALUES MUST BE OF SAME SIZE
    "pub": "CryptoChati-PUB", #Public key
    "key": "CryptoChati-KEY", #Encrypted key for next message
    "sig": "CryptoChati-SIG", #Signature of next message
    "enc": "CryptoChati-ENC", #Encrypted text
}
PREFIXSIZE = len(PREFIXES["pub"])

class MsgWrapper:
    # Base94
    ALPHABET = string.digits + string.ascii_letters + string.punctuation
    ALPHABET_LOOKUP = dict((char, i) for (i, char) in enumerate(ALPHABET))
    BASE = len(ALPHABET)
    
    def __init__(self):
        pass
        
    @classmethod
    def wrap(self, type, data, nick):
        #print "wrap:", type, str(data)[:80], nick
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
        #reverse and remove leading \x01
        return s[-2::-1]


class Conversations(dict):
    def get(self, nick):
        for i in self.iterkeys():
            if xchat.nickcmp(nick, i) == 0:
                nick = i
        
        if not self.has_key(nick):
            super(Conversations, self).__setitem__(nick, {
                "publickey": "",
                #Encrypted 
                "txtkey": "",
                "message": "",
                "signature": "",
                #Numer of messages left until showing "Not rotating key"
                #warning.
                "nextrcvsign": 0,
                "nextsndsign": 0,
                "sndtxtkey": "",
                "sndpublickey": True
            })
        
        return super(Conversations, self).get(nick)
    
    def reset(self, nick):
        conversation = self.get(nick)
        conversation["nextrcvsign"] = 0
        conversation["nextsndsign"] = 0
        conversation["sndpublickey"] = True
        
        
    
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

class Encryptor:
    #List of friend nicks
    friends = []
    #Public keys dictionary
    keys = Keys()
    #Sending public key to others
    sendPubKey = True
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

    def quithook(self, word, word_eol, userdata):
        # print "quit:", word, word_eol, userdata
        nick = word[0]
        
        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(interlocutor, friend) == 0:
                sigue = True
                break
        if sigue:
            #Reset the quitting-friend conversation
            self.conversations.reset(nick)
        
        return xchat.EAT_NONE



    def cipher(self, string, nick):
        conversation = self.conversations.get(nick)
        
        if conversation["nextsndsign"] < 1:
            newKey = self.randfunc(32)
            # Don't let key having \0 character
            while "\0" in newKey:
                newKey = self.randfunc(32)
        else:
            newKey = conversation["sndtxtkey"]
            newKey = newKey[1:] + newKey[0]
        
        #print "cipher:", newKey
        conversation["sndtxtkey"] = newKey
        
        keyText = self.keys[nick].encrypt(newKey, "")[0]
        
        enc = AES.new(newKey)
        #Fill it with null until reaching block size
        newString = string + "\0" * (enc.block_size - (len(string) % enc.block_size))
        newString = enc.encrypt(newString)

        return keyText, newString



    def decipher(self, key, data):
        #print "decipher:", self.privKey.decrypt(key)
        enc = AES.new(self.privKey.decrypt(key))

        return enc.decrypt(data).replace("\0", "")
        

        
    def sign(self, text):
        hash = hashlib.sha1(text).digest()
        return self.privKey.sign(hash, self.randfunc(16))
        
    def verify(self, text, data, interlocutor):
        pubkey = self.keys[interlocutor]
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
            cPickle.dump(Keys(), file)
            file.close()
        with open(self.keysPath, "rb") as file:
            self.keys = cPickle.load(file)
            assert isinstance(self.keys, Keys)
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
        
        
        prefix, data = word_eol[1][0:PREFIXSIZE], word_eol[1][PREFIXSIZE:]
        conversation = self.conversations.get(interlocutor)
        #Check for a "public key" type message
        if prefix == PREFIXES["pub"]:
            try:
                pubKey = cPickle.loads(MsgWrapper.baseX2str(data))
                assert isinstance(pubKey, RSA.RSAobj_c)
                #Caution: negative comparation "!=" doesn't work for RSA
                #objects. It's always True, so you must use "not ==" instead.
                if self.keys.has_key(interlocutor) and \
                    not self.keys.get(interlocutor) == pubKey:
                    print "Cryptochati WARNING: Your interlocutor's public " \
                        "key has changed. She may be an impostor!!"
                self.keys[interlocutor] = pubKey
                file = open(self.keysPath, "wb")
                cPickle.dump(self.keys, file)
                file.close()
                conversation["publickey"] = pubKey
                self.conversations.reset(interlocutor)
                
                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst        
        
        elif prefix == PREFIXES["key"]:
            conversation["txtkey"] = MsgWrapper.baseX2str(data)
            
            return xchat.EAT_XCHAT
            
        elif prefix == PREFIXES["sig"]:
            try:
                verified = False
                conversation["signature"] = MsgWrapper.baseX2dec(data)
                if self.verify(conversation["txtkey"],
                    (conversation["signature"], ), interlocutor):
                    verified = True
            except Exception as inst:
                self.conversations.reset(interlocutor)
                print inst
            if verified:
                conversation["signature"] = ""
                conversation["nextrcvsign"] = 16
            else:
                print "Cryptochati WARNING: Bad signature. " \
                    "Your interlocutor may be an impostor!!"
            
            return xchat.EAT_XCHAT
        
        elif prefix == PREFIXES["enc"]:
            try:
                decoded = self.decipher(conversation["txtkey"],
                    MsgWrapper.baseX2str(data))
                self.sendPubKey = False
                conversation["message"] = decoded
                
                num = conversation["nextrcvsign"]
                if num > 0:
                    conversation["nextrcvsign"] = num - 1
                else:
                    print "Cryptochati WARNING: No rotating incoming key. " \
                        "Your interlocutor is not following the security " \
                        "protocol."
                
                xchat.emit_print(userdata, self.KEY_SYMBOL + word[0],
                    conversation["message"])
                conversation["message"] = -1
                # Rotate txtkey for next message
                txtkey = self.privKey.decrypt(conversation["txtkey"])
                conversation["txtkey"] = self.privKey.encrypt(txtkey[1:] + txtkey[0], "")[0]
                
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
            if conversation["nextsndsign"] < 1:
                txtSignature = self.sign(txtKey)
                #Send key
                MsgWrapper.wrap("key", txtKey, interlocutor)
                #Send signature
                MsgWrapper.wrap("sig", txtSignature[0], interlocutor)
                conversation["nextsndsign"] = 15 #just used one
            else:
                num = conversation["nextsndsign"]
                conversation["nextsndsign"] = num - 1
            #Send real message encrypted raw
            MsgWrapper.wrap("enc", encryptedTxt, interlocutor)
            
            #Show real message unencrypted on chat screen
            xchat.emit_print("Your Message", self.KEY_SYMBOL +
                xchat.get_info("nick"), text)
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
