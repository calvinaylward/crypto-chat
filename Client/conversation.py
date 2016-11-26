from config import *
from message import Message
from base64 import b64encode
from base64 import b64decode
import json
import os.path
import os
from time import sleep
from threading import Thread
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

state = INIT

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.list_of_users = self.manager.get_participants(self.id)
        self.owner = self.list_of_users[len(self.list_of_users)-1]
        self.user_public_key = None
        self.private_key = None
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True
        self.users_init = []
        self.key_pair =[]
        self.RSA_key = None

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)


    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''

        global state

        #state = START

        # You can use this function to initiate your key exchange
		# Useful stuff that you may need:
		# - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: l
        # You may need to send some init message from this point of your code
		# you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
		# replace this with anything needed for your key exchange

        user = self.manager.user_name


        privateFile = "user_"+user+"_privatekey.txt"
        publicFile = "user_"+user+"_publickey.txt"
        #print list_of_users
        #print os.path

        if os.path.exists(os.getcwd() + "/" + privateFile) and os.access(privateFile, os.R_OK) and os.path.exists(os.getcwd() + "/" +publicFile) and os.access(publicFile, os.R_OK):

            with open(publicFile, "r") as pF:
                self.user_public_key = RSA.importKey(pF.read())
            pF.close()

            with open(privateFile, "r") as f:
                self.private_key = RSA.importKey(f.read());
            f.close()

        else:
            self.RSA_key = RSA.generate(2048)
            self.private_key = key.exportKey()
            self.user_public_key = key.publickey().exportKey()

            with open(privateFile, "w") as f:
                f.write(key.exportKey('PEM'))
            f.close()

            with open(publicFile, "w") as pF:
                pF.write(key.publickey().exportKey('PEM'))
            pF.close()

        print "Key set up complete"


        folderPath = "Public_keys/"
        fileString = "_publickey.txt"
        for u in self.list_of_users:
                with open(folderPath + u + fileString, "r") as keyIn:
                    self.users_init.append(RSA.importKey(keyIn.read()))
                keyIn.close()

        #for creator only
        if user == self.owner:
            print self.users_init
            print "\n"
            print self.user_public_key
            count = 0
            for u in self.list_of_users:
                if u != user:

                        cipher = PKCS1_OAEP.new(self.users_init[count])
                        data = user.encode('utf-8') + u.encode('utf-8')
                        msg = b64encode(cipher.encrypt(data))
                        self.manager.post_message_to_conversation(msg)
                count+=1

            state = STARTED

        else :
            #not the owner/ request key / listen for key
            state = LISTENING
            print "wait"




        #data = send_to + sent_from + nonce
        #data = "Elon/Bill/1343"
        #sign with sent_from's private key
        #encrypt with send_to's public key
        #self.manager.post_message_to_conversation(data)







        #if user != self.owner:
        #    self.manager.request_keys()




    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''
        user = self.manager.user

        if user == self.owner and state == STARTED:
            print "user STARTED"

            #reply with nonce from other participants
            cipher_STARTED = PKCS1_OAEP.new(self.private_key)
            buf_STARTED = cipher_STARTED.decrypt(msg_raw)
            index = buf_STARTED.index('|')
            buf_NAMES = buf_STARTED[:index]
            nonce_STARTED = buf_STARTED[index+1:]
            if(owner_str + user) == buf_NAMES :
                #correct response
                #generate keys
                session_key = SHA256.new(self.user_public_key)
                session_key = session_key[0:32]
                mac_key = Random.get_random_bytes(32)
                iv_GENERATED = Random.new().read(AES.block_size)
                self.key_pair = [session_key , mac_key]
                state = GENERATED


            else:
                #print bad message (need to account for multiple participants TODO: use array!) state and nonce
                print "Y U DO DIS"
                return

            #send keys
            nonce_GENERATED = Random.new().read(16)
            data = user + "|" + nonce_GENERATED + "|" + self.key_pair + "|" + iv_GENERATED


            #for loop through users state array if they are state == GENERATED then send them this message
            user_index = self.list_of_users.index(owner_str)
            cipher_GENERATED = PKCS1_OAEP.new(self.users_init[user_index])
            encrypted_msg = cipher_GENERATED.encrypt(data.encode('utf-8'))

            data2 = nonce_STARTED + encrypted_msg

            #create sign
            h = SHA.new(data2)

            signer = PCKS1_v1_5.new(self.private_key)
            signed_data2 = b64encode(signer.sign(data2))

            #msg = b64encode(cipher.encrypt(data))
            #self.manager.post_message_to_conversation(msg)


            #TODO send nonce_STARTED + iv + encrypted_msg + signed_data2
            #start timer
            #change state? in GENERATED right now



        elif state == LISTENING:#not owner listening for initial msg
            cipher1 = PKCS1_OAEP.new(self.private_key)
            buf = b64decode(msg_raw)
            decrypted_message = cipher.decrypt(buf)


            msg_check = self.owner + user
            print msg_check
            if decrypted_message != msg_check:
                print "Invalid message"
                return
                #throw an exception?
            else:
                print "Valid message"

            #generate Nonce
            nonce_user = Random.new().read(16)
            reply_message = user + self.owner + "|" + nonce_user
            pubkeystr = self.users_init[len(self.list_of_users) -1]

            pubkey = RSA.importKey(pubkeystr)
            cipher2 = PKCS1_OAEP.new(pubkey)


            self.process_outgoing_message(cipher2.encrypt(reply_message), True)
            #TODO
            #start a timer for key freshness

            #change state
            state = FIRST_NONCE

        elif state == FIRST_NONCE:
            print state
            #TODO
            #receiving key message from the creator
            #check incoming nonce against nonce_user and make sure timer hasn't expired
            #save the iv
            #decrypt the third part of the message A |Na|K|IV with self.private_key
            #check iv values
            #Check signature of last part of the message against hashed part of third part
            #e.g. msg = A |Na|K|IV, h = SHA256.new(msg) == unsigned(signature) / maybe we use verify?
            # now we have the new session key, iv and a nonce from the creator
            # respond with E(B|NA|K)PuA , E(E(B|NA|K)PuA)PrB
            # second part is signed of the first part
            #change state to FINAL_CHECK
        elif state == GENERATED :
            print state
            #TODO
            # creator waiting for final response from participants
            # parse msg = B |Na|K|
            # check if Na == nonce_GENERATED for user B
            #make sure nonce is received in enough time to be considered valid
            # check if K = self.key_pair
            #verify signature of second part of message
            #state == VERIFIED

        if state == VERIFIED or state == FINAL_CHECK: #we can probably make these the same
            kfile = open("user_" + user + "_privatekey.txt")
            keystr = kfile.read()
            kfile.close()

            private_key = RSA.importKey(keystr)
            cipher = PKCS1_OAEP.new(private_key)

            plain_text = cipher.decrypt(msg_raw)

            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decoded_msg,
                owner_str=owner_str
            )

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''

        #TODO encrypt with self.key_pair

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        # process outgoing message here
		# example is base64 encoding, extend this with any crypto processing of your protocol
        encoded_msg = base64.encodestring(msg_raw)

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)
