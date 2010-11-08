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

Cryptochati aims to be a secure and easy to use encryption plugin for XChat.
It's inspired (in concept, not code) in Pidgin-Encryption plugin.

Installation:
    1) You must have installed the pycrypto module. If you are under Debian or
    Ubuntu, simply install "python-crypto" package:

    $ sudo apt-get install python-crypto
    
    Otherwise, grab it from http://www.dlitz.net/software/pycrypto/
       
    2) Copy the file named "cryptochati.py" in the "~/.xchat2/" directory
    
    3) Create/edit manually the "friends.txt" file into Cryptochati
    configuration directory "~/.xchat2/cryptochati.conf/friends.txt". You'll
    have to create both the "cryptochati.conf" subdirectory and the
    "friends.txt" file if you have never run the plugin before. Add one nick
    per line.

Running:
    The plugin should be autoloaded the next time XChat start. But you can
	launch it manually with the following command (in XChat):
	
	/py load cryptochati.py

XChat commands:
    There are no commands at the moment. You must manually edit configuration
    files.
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


PREFIXES = { # MUST BE 15 CHARS LONG
    "enc": "CryptoChati-ENC", #Encrypted text
    "pub": "CryptoChati-PUB", #Public key
    "sig": "CryptoChati-SIG" #Signature of next message
}


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
    
    def __init__(self):
        #Decode hooks
        xchat.hook_print("Private Message", self.decode, "Private Message")
        xchat.hook_print("Private Message to Dialog", self.decode, "Private Message to Dialog")
        
        #Generic encode hook
        self.allhook = xchat.hook_command("", self.encode)
        
        #Random generator
        self.randfunc = RandomPool().get_bytes
        
        #Initialize configuration directory
        confDir = "cryptochati.conf/"
        if os.path.isdir(".xchat2"):
            confDir = ".xchat2/" + confDir
        if not os.path.isdir(confDir):
            os.mkdir(confDir, 0700)
        
        #Friends file
        self.friendsPath = confDir + "friends.txt"
        #Private key file
        self.myKeyPath = confDir + "my.key"
        #Friends' public keys file
        self.keysPath = confDir + "public.keys"
        
        #Create/load configuration
        self.openConfiguration()



    def cipher(self, cadena, nick):
        res = ""
        nuevaClave = self.randfunc(32)
        while "\0" in nuevaClave:
            nuevaClave = self.randfunc(32)
        
        res += self.keys[nick].encrypt(nuevaClave, "")[0].encode("base64").replace("\n", "")
        
        res += "-"
        
        enc = AES.new(nuevaClave)
        #Fill it with null until reaching block size
        cadena += "\0" * (enc.block_size - (len(cadena) % enc.block_size))

        cadena = enc.encrypt(cadena).encode('base64').replace("\n", "")
        res += cadena
        return res



    def decipher(self, cadena):
        #TODO
        key, message = cadena.split("-")
        enc = AES.new(self.privKey.decrypt(key.decode("base64")))

        return enc.decrypt(message.decode('base64')).replace("\0", "")
        

        
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
        
        actual = xchat.get_info("channel")
        
        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(actual, friend) == 0:
                sigue = True
                break
        if not sigue:
            #Take as it comes (from no-friend)
            return xchat.EAT_NONE
        
        
        prefix = word[1][0:15]
        #Check for a "public key" type message
        if prefix == PREFIXES["pub"]:
            try:
                pubKey = cPickle.loads(word[1][15:].decode("base64"))
                assert isinstance(pubKey, RSA.RSAobj_c)
                self.keys[actual.lower()] = pubKey
                file = open(self.keysPath, "wb")
                cPickle.dump(self.keys, file)
                file.close()
                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst
                
        elif prefix == PREFIXES["enc"]:
            try:
                decoded = self.decipher(word[1][15:])
                xchat.emit_print(userdata, "e< " + word[0], decoded)
                self.sendPubKey = False
                return xchat.EAT_XCHAT
            except Exception as inst:
                print inst
        
        return xchat.EAT_NONE

	

    def encode(self, word, word_eol, userdata):
        #print "encode", word, word_eol
        actual = xchat.get_context().get_info("channel")
        sigue = False
        for friend in self.friends:
            if xchat.nickcmp(actual, friend) == 0:
               sigue = True
        if not sigue:
            #Send text as it comes (unencrypted to a no-friend)
            return xchat.EAT_NONE            

        prefix = word[0][0:15]
        if prefix in PREFIXES.itervalues():
            #Send text as it comes (formated for a friend)
            return xchat.EAT_NONE
        #Send publick key, invisible to user (raw)
        if self.sendPubKey:
            xchat.get_context().command("raw privmsg " + actual + " " +
                PREFIXES["pub"] + cPickle.dumps(self.pubKey).encode('base64')
                .replace("\n", ""))

        if self.keys.has_key(actual.lower()):
            #Send real message encrypted raw
            xchat.get_context().command("raw privmsg " + actual + " " +
                PREFIXES["enc"] + self.cipher(word_eol[0], actual.lower()))
            #Show real message unencrypted on chat screen
            xchat.emit_print("Your Message", "e> " + xchat.get_info("nick"),
                word_eol[0])
            return xchat.EAT_ALL
        else:
            #xchat.get_context().command("privmsg " + actual + " " + word_eol[0
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
