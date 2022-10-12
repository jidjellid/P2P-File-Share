#!/usr/bin/env python3

import os
from random import randrange
from re import I
import time
import requests
import ecdsa
import hashlib
import socket
import binascii
from hashlib import sha256
from anytree import AnyNode, RenderTree, node
from queue import Queue
from threading import Thread
import time

NAME = "El jafar"
DEBUG = False
EMPTY_HASH = int("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",16).to_bytes(32, byteorder='big')#String for an empty hash converted into bytes
URL_API = 'https://jch.irif.fr:8082'
RANGE = 4000000000
REMOTE_FOLDERS = "RemoteFolders"
PRIVATE_FOLDERS = "PrivateFolder"

# Basic settings for the UDP client
localPort   = 8089
bufferSize  = 1500

congestionWindows = 1

# Our private key
privateKey = ecdsa.SigningKey.generate(
    curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256,
)

# Bind to the local ip to receive UDP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', localPort))

# Global variable used to know when to display the tree again
updateTree = False

# Array to store all the nodes for whom GetDatum have been sent but no response has come yet. 
# [(packet,(ip,port),timeSent)]
waitList = []

# Array to store all the node for whom GetDatum should be sent. Used for congestion control
# [(packet,(ip,port),expectResponseBoolean)]
packetsToSend = []

# Any node in this array will have his descendants downloaded.
# [node]
nodesToDownload = []

# Index of the current peer in the peer list we are connected to
currentPeer = None

# Datalist, is a directory
privateTree = AnyNode(hash=EMPTY_HASH,type=2,name="Root")
remoteTree = AnyNode(hash=EMPTY_HASH,type=2,name="Root")

# Peerlist data
# [name,(ip,port),id,lastSeenTime]
peerList = []

# Public key list
keyList = [] # Not used yet

def dbg(name: str, msg):
    if DEBUG: 
        print("-----------")
        print(name + ' ' + msg)  


def findNodeHash(h,tree):
    '''
        Returns a Node or None based weither the val parameter matches 
        either the name or the hash of a node in our tree. 
        Val can be either a String or Bytes.
    '''
    if hasattr(tree,"hash"):
        if type(h) == bytes:
            if tree.hash == h:
                return tree
            else:
                try:
                    # Convert string to bytes then test
                    if tree.hash == int(h,16).to_bytes(32, byteorder='big'):
                        return tree
                except:
                    pass

    for node in tree.descendants:
        # Check if h == hash
        if hasattr(node,"hash"):
            if type(h) == bytes:
                if node.hash == h:
                    return node
            else:
                try:
                    # Convert string to bytes then test
                    if node.hash == int(h,16).to_bytes(32, byteorder='big'):
                        return node
                except:
                    pass
    return None


def findNodeName(name):
    '''
        Returns a Node or None based weither the val parameter matches 
        either the name or the hash of a node in our tree. 
        Val can be either a String or Bytes.
    '''
    if remoteTree.name == name:
        return [remoteTree]
    nodeArray = []
    for node in remoteTree.descendants:
        # Check if name == name
        if hasattr(node,"name") and type(name) == str:
            if node.name[:len(name)] == name:
                nodeArray.append(node)
    return nodeArray

def printTree(rootNode):
    if currentPeer != None:
        print("Printing the tree of",currentPeer[0],"\n")
    for pre, _, node in RenderTree(rootNode):
        if(node.type == 0):
            if not hasattr(node,"name"):
                if(rootNode != privateTree):
                    print(pre, "Subchunk -",binascii.hexlify(node.hash))
            else:
                print(pre, "File -",node.name,"-",binascii.hexlify(node.hash))
        elif(node.type == 1):
            if not hasattr(node,"name"):
                if(rootNode != privateTree):
                    print(pre, "Subtree -",binascii.hexlify(node.hash))
            else:
                print(pre, "BigFile -",node.name,"-",binascii.hexlify(node.hash))
        elif(node.type == 2):
            if not hasattr(node,"name"):
                print(pre, "Dir - ? -",binascii.hexlify(node.hash))
            else:
                print(pre, "Dir -",node.name,"-",binascii.hexlify(node.hash))



def produceHash(node):
    '''
        Given a node, create its associated hash based on the hash of its children
    '''
    h = hashlib.sha256()
    h.update((node.type).to_bytes(1, byteorder='big'))

    if node.type == 0:
        h.update(node.value)
    elif node.type == 1:
        for n in node.children:
            h.update(n.hash)
    elif node.type == 2:
        for n in node.children:
            if not hasattr(n,"name"):
                h.update("".encode())
            else:
                paddedName = bytearray((n.name).encode('utf-8'))#Name of the file
                paddedName.extend(bytearray(32 - len(n.name)))#Additionnal padding
                h.update(paddedName)
            h.update(n.hash)    
    return h.digest()

def pathOfNode(node, peer):
    #Create folder path
    path = node.name.rstrip('\x00')

    while node.parent != None:
        node = node.parent
        if hasattr(node,"name"):
            path = node.name.rstrip('\x00') + "/" + path
        else:
            return REMOTE_FOLDERS + "/" + peer[0] + "/" + binascii.hexlify(node.hash).decode() + "/" + path

    return REMOTE_FOLDERS + "/" + peer[0]+ "/" + path

def addAnyNode(hash,value,peer,id):
    '''
    Add a node to the tree based on its hash and value. Also sends error message to wrong packets and updates the global arrays when a reception or addition is made
    '''

    addr = peer[1]
    # Type of the packet
    dataType = value[0]
    # Value of the packet
    dataValue = value[1:]

    # Select the node to use as the current node based on hash. 
    currentNode = findNodeHash(hash,remoteTree)

    # If none is found, assume that the current node is
    # the root since the hash should already have been added in our tree on previous additions
    if currentNode == None :
        currentNode = remoteTree

    # Update the type of the current node (0,1,2)
    currentNode.type = dataType

    # print("Received packet of type",dataType)

    if dataType == 0: # Chunk
        # Check maximum length
        if len(dataValue) > 1024 :
            text = "Error, invalid length when receiving Datum for hash '" + binascii.hexlify(currentNode.hash).decode() + "', expected length<1024 but got a len : " + str(len(dataValue)) + "instead"
            replyByte = buildError(id,text)
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))
        # Set the value attribute of the current node
        currentNode.value = dataValue

    elif dataType == 1: # Tree
        # Check for valid length
        if len(dataValue)%32 != 0:
            text = "Error, invalid length when receiving Datum for hash '" + binascii.hexlify(currentNode.hash).decode() + "', expected len(value)%32 == 0 but got " + str(len(dataValue)%64) + "instead"
            replyByte = buildError(id,text)
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))
        
        # Parse the value
        for i in range(0,len(dataValue),32):
            valueHash = dataValue[i:i+32]

            # Check if the node already exists
            nodeAlreadyExists = findNodeHash(valueHash,remoteTree)

            # If the node does not already exist, add it to a list of nodes that we will insert once every node has been checked
            if nodeAlreadyExists == None :
                AnyNode(hash=valueHash,parent=currentNode,type=-1)
            else:
                nodeAlreadyExists.parent = currentNode

            shouldDownload = False

            # Check if the subnodes should be downloaded based on the nodes in nodesToDownload
            for n in nodesToDownload:
                node = n[0]
                if node == currentNode or node in currentNode.ancestors:
                    shouldDownload = True 
                    break  

            if shouldDownload:
                replyByte = buildGetDatum(valueHash)
                packetsToSend.append((replyByte,(addr[0], int(addr[1])),True))
    
    elif dataType == 2: # Directory

        global updateTree
        # Make the tree get displayed again
        updateTree = True

        #Create folder path
        path = None
        if hasattr(currentNode,'name'):
            path = pathOfNode(currentNode,peer)
        else:
            path = REMOTE_FOLDERS + "/" + peer[0] + "/" + binascii.hexlify(currentNode.hash).decode()
        os.makedirs(path, exist_ok=True)

        # Check for valid length
        if len(dataValue)%64 != 0:
            text = "Error, invalid length when receiving Datum for hash '" + binascii.hexlify(currentNode.hash).decode() + "', expected len(value)%64 == 0 but got " + str(len(dataValue)%64) + "instead"
            replyByte = buildError(id,text)
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

        # Parse the value
        for i in range(0,len(dataValue),64):
            valueName = dataValue[i:i+32]
            valueHash = dataValue[i+32:i+64]

            # Check if the node already exists
            nodeAlreadyExists = findNodeHash(valueHash,remoteTree)

            # If the node does not already exist, add it to a list of nodes that we will insert once every node has been checked
            if(nodeAlreadyExists == None):
                # Add the new node with its attributes
                AnyNode(hash=valueHash, name=valueName.decode(), parent=currentNode,type=-1)

                #print("Sending GetDatum for hash :",binascii.hexlify(valueHash),"to :",(addr[0], int(addr[1])))
            else:
                nodeAlreadyExists.parent = currentNode
                nodeAlreadyExists.name = valueName.decode()

            # Send a GetDatum to get the value and childrens of our newly added node
            replyByte = buildGetDatum(valueHash)
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),True))

    #print("Current addNode addr :",(addr[0], int(addr[1])))
    remoteTree.hash = produceHash(remoteTree)


def byteBuilder(id, dataType, body = ""):
    '''
        Builds and returns a byte according to the protocol and parameters
    '''
    byteBuild = bytearray()
    byteBuild.extend((id).to_bytes(4, byteorder='big'))
    byteBuild.extend((dataType).to_bytes(1, byteorder='big'))
    byteBuild.extend((len(body)).to_bytes(2, byteorder='big'))
    byteBuild.extend(body)
    byteBuild.extend(privateKey.sign(byteBuild))

    # dbg("Final build:", binascii.hexlify(byteBuild))
    # dbg("Text:'", byteBuild[7:(7+len(body))])

    return byteBuild

def buildHelloByte():
    bodyByte = bytearray()
    # Near max 4 bytes unsigned possible value
    bodyByte.extend((0).to_bytes(4, byteorder='big'))
    bodyByte.extend(str.encode(NAME))

    # dbg("Hello byte:", binascii.hexlify(byteBuilder(peerId, 0, bodyByte)))

    return byteBuilder(randrange(RANGE), 0, bodyByte)

def buildHelloReplyByte(id):
    bodyByte = bytearray()
    bodyByte.extend((0).to_bytes(4, byteorder='big'))
    bodyByte.extend(str.encode(NAME))
    return byteBuilder(id ,128, bodyByte)

def buildPublicKeyByte():
    return byteBuilder(randrange(RANGE), 1)

def buildPublicKeyReplyByte(id):
    return byteBuilder(id, 129)

def buildRoot():
    return byteBuilder(randrange(RANGE), 2, privateTree.hash)

def buildRootReply(id):
    return byteBuilder(id, 130, privateTree.hash)

def buildGetDatum(hash):
    return byteBuilder(randrange(RANGE),3,hash)

def buildDatum(id, hash):
    data = findNodeHash(hash,privateTree)

    # Check if node of said hash actually exists and if it's data is complete
    if data != None:
        bodyByte = bytearray()
        bodyByte.extend(data.hash)
        bodyByte.extend((data.type).to_bytes(1, byteorder='big'))

        if data.type == 0:
            bodyByte.extend(data.value)
        elif data.type == 1:
            for i in data.children:
                bodyByte.extend(i.hash)
        elif data.type == 2:
            for i in data.children:
                paddedName = bytearray((i.name).encode('utf-8'))
                paddedName.extend(bytearray(32 - len(i.name)))
                bodyByte.extend(paddedName)
                bodyByte.extend(i.hash)

        return byteBuilder(id, 131, bodyByte) #Datum

    return byteBuilder(id, 132, hash) #NoDatum

def buildNatTraversalRequest():
    return byteBuilder(randrange(RANGE),133)

def buildError(id, message):
    print("Sent error with ",message)
    return byteBuilder(id, 254, str.encode(message))


def processPacket(packet, addr):
    '''
        Process a received packet and react accordingly to the protocol
    '''
    id = int.from_bytes(packet[0:4],byteorder='big', signed=False)
    dataType = int.from_bytes(packet[4:5],byteorder='big', signed=False)
    length = int.from_bytes(packet[5:7],byteorder='big', signed=False)

    # Remove received packets from the waitList
    for w in waitList:
        # Get the id from the parsed packet
        packetId = int.from_bytes(w[0][0:4],byteorder='big', signed=False)
        if packetId == id:
            # Remove the packet from the waitList with the id from the packet received
            waitList.remove(w)

    #print("Received packet from",addr,"of dataType",dataType)

    if(dataType == 0): #Hello
        replyByte = buildHelloReplyByte(id)
        packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))
        
        sendBack = True
        for p in peerList:
            if addr[0] == p[1][0] and addr[1] == p[1][1]:
                sendBack = False
        
        if sendBack:
            replyByte = buildHelloByte()
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))


        #print("Replied with HelloReply :",binascii.hexlify(replyByte))    
    elif(dataType == 128): #HelloReply
        extension = int.from_bytes(packet[7:11],byteorder='big', signed=False)
        name = packet[11:11+length-4]
        try:
            name = name.decode()
        except:
            print("Sent error to ",id,": for bad name")
            replyByte = buildError(id,("Error, could not decode name from HelloReply : ",binascii.hexlify(name)))
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

        matchingPeers = [peer for peer in peerList if peer[0] == name]
        if len(matchingPeers) == 0:
            print("Added",(name,(addr[0],int(addr[1])),id),"to the peer list")
            peerList.append((name,(addr[0],int(addr[1])),id,time.time())) 
        else:
            for p in matchingPeers:
                toList = list(p)
                toList[2] = time.time()
                peerList.remove(p)
                peerList.append(tuple(toList))

    elif dataType == 129 or dataType == 1: #PublicKey & PublicKeyReply   #Does not work
        if dataType == 1:
            replyByte = buildPublicKeyReplyByte(id)
            print("Replied with PublicKeyReply :",binascii.hexlify(replyByte))
            packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

        if length != 0:
            if length == 64:
                index = None

                for i in len(peerList):
                    if peerList[i][2] == id:
                        index = i
                        break
                    
                # Pour parser une clé publique représentée comme une chaîne de 64 octets :
                key = ecdsa.VerifyingKey.from_string(
                    packet[7:7+length], curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256,
                )
                if index != None:
                    keyList[index] = key
                    print("Added",key,"to the key list at",index)
            else:
                print("Sent error to ",id,": length = ",length)
                replyByte = buildError(id,"Wrong length for PublicKeyReply packet : ",length)
                packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

    elif dataType == 2: #Root
        replyByte = buildRootReply(id)
        #print("Replied with Rootreply :",binascii.hexlify(replyByte))
        packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

    elif dataType == 130: #RootReply
        
        if currentPeer != None and addr[0] == currentPeer[1][0] and addr[1] == currentPeer[1][1]:

            body = packet[7:7+length] #Body is a hash

            if remoteTree.hash != body and body != EMPTY_HASH:
                remoteTree.hash = body
                replyByte = buildGetDatum(body)
                packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))
                #print("Replied with GetDatum to the root with hash :",binascii.hexlify(body))

    elif(dataType == 3): #GetDatum
        hash = packet[7:7+length]
        replyByte = buildDatum(id,hash)
        #print("Replied with Datum :",binascii.hexlify(replyByte))
        packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

    elif(dataType == 131): #Datum
        hash = packet[7:7+32]
        value = packet[39:39+length-32]

        for p in peerList:
            if addr[0] == p[1][0] and addr[1] == p[1][1]:

                #Verify hash
                computedHash = hashlib.sha256()
                computedHash.update(value)
                computedHash = computedHash.digest()
                
                # Check that the hash in the Datum packet is correct
                if(computedHash != hash):
                    text = "Invalid hash, expected '"+binascii.hexlify(computedHash).decode()+"' but received'"+binascii.hexlify(hash).decode()+"' instead"
                    replyByte = buildError(id,text)
                    packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))
                    return

                #print("Received datum of hash :",binascii.hexlify(hash))
                addAnyNode(hash,value,p,id)

    elif(dataType == 132): #NoDatum
        hash = packet[7:7+length]
        print("NoDatum received for hash :",binascii.hexlify(hash))
        n = findNodeHash(hash,remoteTree)
        if(n != None):
            n.parent = None
        

    elif(dataType == 133): #NatTraversalRequest
        pass

    elif(dataType == 134): #NatTraversal
        replyByte = buildError(id,"We do not support NatTraversal, sorry :(")
        print("Replied with Error to NatTraversal :",binascii.hexlify(replyByte))
        packetsToSend.append((replyByte,(addr[0], int(addr[1])),False))

    elif(dataType == 254): #Error
        print("/!\ Error received :",packet[7:7+length].decode(),"/!\ ")

def listenForXUDP(q,exitQ):
    while(1):
        if(exitQ.qsize() != 0):
            exit(0)
        try:
            q.put(sock.recvfrom(1500))   
        except:
            pass

#Put batches of 32 node from nodeList into another list and return it
def linkNodes(nodeList):
    newList = []
    while(len(nodeList) != 0):
        n = AnyNode(hash=EMPTY_HASH,type=1)
        newList.append(n)
        for i in range(32):
            if len(nodeList) == 0:
                break
            nodeList[0].parent = n
            del nodeList[0]
    return newList

# Recursively create the nodes for the private tree
def fetchPrivateTree(path, node):
    subfolders = [name for name in os.listdir(path) if os.path.isdir(path + "/" + name)]
    subfiles = [name for name in os.listdir(path) if os.path.isfile(path + "/" + name)]
    
    #Add folders for the current path and node
    for name in subfolders:
        filePath = path + "/" + name
        n = AnyNode(hash=EMPTY_HASH,type=2,name=name[:min(32,len(name))],parent=node)
        fetchPrivateTree(filePath,n)

    for name in subfiles:
        filePath = path + "/" + name
        if os.path.getsize(filePath) > 1024:
            nodeList = []
            f = open(filePath,"rb") 
            while True:
                val = f.read(1024)
                if not val:
                    break
                nodeList.append(AnyNode(hash=EMPTY_HASH,type=0,value=val))
            
            while(len(nodeList) != 1):
                nodeList = linkNodes(nodeList)

            nodeList[0].name=name[:min(32,len(name))]
            nodeList[0].parent=node
            
        else:
            f = open(filePath,"rb")
            AnyNode(hash=EMPTY_HASH,type=0,value=f.read(1024),parent=node,name=name[:min(32,len(name))])

def isDownloaded(node):
    #If the node is a type 0 and has a value, it is downloaded
    if hasattr(node,"type") and node.type == 0 and hasattr(node,"value"):
        return True

    #If the node is in flight or waiting to be sent, it is not downloaded yet
    if(node in waitList or node in packetsToSend):
        return False
    for n in node.descendants:
        if(n in waitList or n in packetsToSend or n.type == -1):
            return False

    #If the node is either a type 1 or 2, check if every one of it's descendants have been downloaded
    for d in node.descendants:
        if d.type == -1:
            return False
    return True

def writeNode(node,peer):
    
    byteBuild = bytearray()

    if node.type == 0:#If the downloaded node is a single Chunk
        byteBuild.extend(node.value)
    elif node.type == 1:#If the downloaded node is a Tree
        for i in node.descendants:
            if i.type == 0:
                byteBuild.extend(i.value)

    path = None
    if hasattr(node,"name"):
        path = pathOfNode(node,peer)
    else:
        path = REMOTE_FOLDERS + "/" + peer[0] + "/" + binascii.hexlify(node.hash).decode()

    united = '/'.join(path.split("/")[:-1])

    if not os.path.exists(united):
        os.makedirs(united, exist_ok=True)
                    
    f = open(path,"w+b")
    f.write(byteBuild)
    f.close()

def fetchPeersFromServer():
    r = requests.get(URL_API + '/peers/')

    if r.status_code == 200 or r.status_code == 204:
    # Checks every peer in the received list and send an hello packet to each of them

        potentialPeerList = r.text.split('\n')[:-1]

        for i in potentialPeerList:

            fetch = requests.get(URL_API + '/peers/' + i.rstrip('\r\n') + '/' + "addresses")

            if fetch.status_code == 404:
                print("404 found for this peer")
                continue

            addrList = fetch.text.split('\n')[:-1]

            # Do not send an hello if the peer is myself or is already in the list
            if i == NAME or [item for item in peerList if item[0] == i]:
                continue

            print("Fetching",i,"addresses list")

            for addr in addrList:
                port = addr[addr.rfind(":")+1:]
                ip = addr[:addr.rfind(":")]
                        
                print("Testing",addr,"for connection")

                replyByte = buildHelloByte()
                packetsToSend.append((replyByte,(ip, int(port)),False))
    else:
        print("Unable to reach main server")

def hostServer(out_q):    

    timer1 = 0
    timer2 = time.time()
    sock.settimeout(1)
    
    lostPacketCounter = 0

    global congestionWindows
    global updateTree
    global currentPeer
    global remoteTree
    global privateTree
    global peerList
    global waitList
    global packetsToSend
    global nodesToDownload

    if not os.path.exists(REMOTE_FOLDERS):
        os.mkdir(REMOTE_FOLDERS)

    recvFromQ = Queue()
    exitQ = Queue()
    recvFromThread = Thread(target=listenForXUDP,args=(recvFromQ,exitQ,))
    recvFromThread.start()


    while True:

        # Code that runs on a 1s timer
        # Get the missing data that was never sent
        if(time.time() - timer2 > 1):
        
            '''
            print("\nCongestion window :",congestionWindows)
            print("Packets to send list size :",len(packetsToSend))
            print("Waiting list size :",len(waitList))
            print("Lost packet counter :",lostPacketCounter,"\n")
            '''

            if len(waitList) > 0:
                for n in waitList:
                    # A packet is considered lost when no answers has been made for 2 seconds
                    if time.time() - n[2] > 2:
                        lostPacketCounter += 1
                        # Adjust congestion windows for the packet loss
                        congestionWindows = max(1,congestionWindows // 2)
                        replyByte = n[0]
                        addr = n[1]
                        waitList.remove(n)
                        packetsToSend.append((replyByte,(addr[0], int(addr[1])),True))

            #Check if the node to download has been fully downloaded
            for n in nodesToDownload:
                node = n[0]
                peer = n[1]
                if isDownloaded(node):

                    #Print for clarity
                    if hasattr(node,"name"):
                        print(node.name,"has finished downloading !")
                    else:
                        print(binascii.hexlify(node.hash),"has finished downloading !")
                    
                    if node.type == 2:#If the downloaded node is a directory
                        for d in node.descendants:
                            if hasattr(d,"name") and d.type != 2:
                                writeNode(d,peer)
                    else:
                        writeNode(node,peer)
                        
                    if(remoteTree.hash != EMPTY_HASH):
                        global updateTree
                        # Make the tree get displayed again
                        updateTree = True

                    nodesToDownload.remove(n)#Remove the node when downloaded

            # Display tree on changes
            if updateTree:
                printTree(remoteTree)
                print()
                updateTree = False

            timer2 = time.time()
        
        # Code that runs on a 30s timer
        if(time.time() - timer1 > 30):

            timer1 = time.time()

            for peer in peerList:
                # Send an hello to every known peer
                packetsToSend.append((buildHelloByte(),(peer[1][0], int(peer[1][1])),False))
                
                # Remove the peer if there was no response for 180s
                if time.time() - peer[2] > 180:
                    peerList.remove(peer)

            fetchPeersFromServer()
                    

        # Process inputs from the client
        if(out_q.qsize() != 0):
            inputs = out_q.get()
            words = inputs.split(" ")
            if(words[0] == "connect" and len(words) > 1):
                seen = False
                for peer in peerList:
                    if peer[0] == " ".join(words[1:]) and currentPeer != peer:
                        seen = True
                        print("Recovering",peer[0],"directory")
                        remoteTree = AnyNode(hash=EMPTY_HASH,type=2,name="Root")
                        nodesToDownload.clear()
                        currentPeer = peer
                        replyByte = buildRoot()
                        packetsToSend.append((replyByte,(peer[1][0], int(peer[1][1])),False))
                        if not os.path.exists(REMOTE_FOLDERS + "/" + currentPeer[0]):
                            os.makedirs(REMOTE_FOLDERS + "/" + currentPeer[0], exist_ok=True)
                        break
                if not seen:
                    print("Name not recognised")

            elif(words[0] == "download" and len(words) > 1):
                if(currentPeer != None):
                    nodeList = findNodeName(" ".join(words[1:]))
                    if len(nodeList) == 0:
                        hashFound = findNodeHash(" ".join(words[1:]),remoteTree)
                        if hashFound != None:
                            nodeList.append(hashFound)
                    
                    if len(nodeList) == 0:
                        print("No data with such name found")
                    elif len(nodeList) == 1:
                        if nodeList[0] != None and currentPeer != None:

                            # Mark the node to download so that all its descendants are downloaded
                            nodesToDownload.append((nodeList[0], currentPeer))

                            # Send GetDatums for the childrens of the node
                            if nodeList[0].type == 0:
                                replyByte = buildGetDatum(nodeList[0].hash)
                                packetsToSend.append((replyByte,(currentPeer[1][0], int(currentPeer[1][1])),True)) # p == addr of peer
                            else:
                                for c in nodeList[0].children:
                                    replyByte = buildGetDatum(c.hash)
                                    packetsToSend.append((replyByte,(currentPeer[1][0], int(currentPeer[1][1])),True)) # p == addr of peer
                            print("Added node with name/hash '"," ".join(words[1:]),"' to the download list")

                    else:
                        print("Multiple datas with such name found, use the entire name or a request with an hash instead :")
                        for i in nodeList:
                            print("     ",i.name,"-",i.hash)
                else:
                    print("Not yet connected to any peer")

            # Request a datum from a peer in the list and an hash
            elif words[0] == "request" and len(words) > 2:
                seen = False
                for p in peerList:
                    if p[0] == " ".join(words[1:(len(words)-1)]):
                        seen = True
                        h = None
                        try:
                            h = int(words[-1],16).to_bytes(32, byteorder='big')
                        except:
                            break
                        
                        n = findNodeHash(h,remoteTree)

                        if(n == None):
                            n = AnyNode(hash=h,parent=remoteTree,type=-1)

                        nodesToDownload.append((n,p))
                        replyByte = buildGetDatum(h)
                        print("Sending request for :",binascii.hexlify(h) )
                        packetsToSend.append((replyByte,(p[1][0], int(p[1][1])),True))#p == addr of peer
                if not seen:
                    print("Name not recognised")

            elif words[0] == "exit":
                exitQ.put(True)
                exit(0)

            elif words[0] in ["peers", "peer"]:
                print("Peers in our list :")
                for i in peerList:
                    print("     ",i[0],"-",i[1])

            elif words[0] in ["display", "print"]:
                if len(words) > 1 and words[1] == "private":
                    print("Printing private tree")
                    printTree(privateTree)
                else:
                    print("Printing remote tree")
                    printTree(remoteTree)

            elif words[0] in ["refresh"]:
                if len(words) > 1 and words[1] == "private":
                    print("Refreshing the private tree")
                    if os.path.exists(PRIVATE_FOLDERS):
                        privateTree = AnyNode(hash=EMPTY_HASH,type=2,name="Root")
                        fetchPrivateTree(PRIVATE_FOLDERS, privateTree)

                        #Compute the hash of the private tree
                        for n in privateTree.descendants:
                            if n.type == 0:
                                n.hash = produceHash(n)
                                while(n.parent != None):
                                    n = n.parent
                                    n.hash = produceHash(n)

                        replyByte = buildRootReply(randrange(RANGE))#Notify the server that our root changed
                        packetsToSend.append((replyByte,('81.194.27.155', 8082),False))#Send a packet to jch to notify that our root changed

                        printTree(privateTree)
                    
                elif len(words) > 1 and words[1] in ["peers","peer"]:
                    print("Refreshing the peers from the server")
                    fetchPeersFromServer()

            else:
                print("Unknown command")

        # Process any incoming packet         
        while recvFromQ.qsize() != 0:
            msg = recvFromQ.get()
            congestionWindows += 1
            processPacket(msg[0], msg[1])
        
        # Process the packets that should be sent
        for p in packetsToSend:
            if len(waitList) < congestionWindows:
                try:#Try to send the packet 
                    sock.sendto(p[0], p[1])
                except:
                    pass
                # If a response is expected, add it to the waitList
                if p[2] == True:
                    waitList.append((p[0], p[1], time.time()))
                packetsToSend.remove(p)
            else:
                break
        time.sleep(0.1)

def hostClient(in_q):
    while True:
        i = input("Enter command : ")
        in_q.put(i)
        if i == "exit":
            exit(0)
        time.sleep(0.1)

#Turn the private folders into a tree
if os.path.exists(PRIVATE_FOLDERS):
    fetchPrivateTree(PRIVATE_FOLDERS, privateTree)

    #Compute the hash of the private tree
    for n in privateTree.descendants:
        if n.type == 0:
            n.hash = produceHash(n)
            while(n.parent != None):
                n = n.parent
                n.hash = produceHash(n)

printTree(privateTree)

q = Queue()
serverThread = Thread(target=hostServer,args=(q,))
clientThread = Thread(target=hostClient,args=(q,))
serverThread.start()
clientThread.start()