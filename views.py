import tkinter
from tkinter import *
import math
import random
from threading import Thread 
from collections import defaultdict
from tkinter import ttk
import matplotlib.pyplot as plt
import numpy as np
import time
import random
import numpy as np
import hmac
import hashlib
import base64
import random
import socket
import pickle
import json
from web3 import Web3, HTTPProvider
import timeit
import ECC
from ZeroKnowledge import ZKProof
from datetime import datetime
import timeit
import pyaes, pbkdf2, binascii, os, secrets
import webbrowser

global mobile
global labels
global mobile_x
global mobile_y
global text
global canvas
global source_list, dest_list, tf1
global filename
global p1,p2,p3
global line1,line2,line3
option = 0
global root
rewards = []
global details
ecc = []
zkp = []
global zkp_proof, details

def getAESKey(): #generating key with PBKDF2 for AES
    password = "s3cr3t*c0d3"
    passwordSalt = '76895'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encryptAES(plaintext): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decryptAES(enc): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def readDetails():
    global details
    details = ""
    blockchain_address = 'http://127.0.0.1:9545' #Blokchain connection IP
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'IOTContract.json' #IOTContract contract code
    deployed_contract_address = '0x1889207f21FDe8284E0C9F4D056f80F36753CE67' #hash address to access counter feit contract
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi) #now calling contract to access data
    details = contract.functions.getPatientData().call()
    print(details)    

def saveDataBlockChain(currentData):
    global details
    global contract
    details = ""
    blockchain_address = 'http://127.0.0.1:9545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'IOTContract.json' #IOTContract contract file
    deployed_contract_address = '0x1889207f21FDe8284E0C9F4D056f80F36753CE67' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    readDetails()
    details+=currentData
    msg = contract.functions.savePatientData(details).transact()
    tx_receipt = web3.eth.waitForTransactionReceipt(msg)
    
def getDistance(iot_x,iot_y,x1,y1):
    flag = False
    for i in range(len(iot_x)):
        dist = math.sqrt((iot_x[i] - x1)*2 + (iot_y[i] - y1)*2)
        if dist < 80:
            flag = True
            break
    return flag

    
def startDataTransferSimulation(message, ecc_sign, zkp_sign, aes_data, text,canvas,line1,line2,x1,y1,x2,y2,x3,y3):
    class SimulationThread(Thread):
        def _init_(self, message, ecc_sign, zkp_sign, aes_data, text,canvas,line1,line2,x1,y1,x2,y2,x3,y3): 
            Thread._init_(self) 
            self.canvas = canvas
            self.line1 = line1
            self.line2 = line2
            self.x1 = x1
            self.y1 = y1
            self.x2 = x2
            self.y2 = y2
            self.x3 = x3
            self.y3 = y3
            self.text = text
            self.message = message
            self.ecc_sign = ecc_sign
            self.zkp_sign = zkp_sign
            self.aes_data = aes_data
             
        def run(self):
            global zkp_proof
            for i in range(0,3):
                self.canvas.delete(self.line1)
                self.canvas.delete(self.line2)
                time.sleep(1)
                self.line1 = canvas.create_line(self.x1, self.y1,self.x2, self.y2,fill='black',width=3)
                self.line2 = canvas.create_line(self.x2, self.y2,self.x3, self.y3,fill='black',width=3)
                time.sleep(1)
            self.canvas.delete(self.line1)
            self.canvas.delete(self.line2)
            canvas.update()
            ecc_verify = ECC.eccVerify(self.ecc_sign, self.message.encode())
            self.text.insert(END,"Generated ECC Sign: "+str(self.ecc_sign)+"\n")
            if ecc_verify:
                self.text.insert(END,"ECC Verification Successful\n")
            else:
                self.text.insert(END,"ECC Verification Failed\n")
            zkp_verify = zkp_proof.verify(message)
            self.text.insert(END,"Generated ZKP Sign: "+str(self.zkp_sign)+"\n")
            if ecc_verify:
                self.text.insert(END,"ZKP Verification Successful\n")
            else:
                self.text.insert(END,"ZKP Verification Failed\n")
            aes_decrypt = decryptAES(self.aes_data)
            text.insert(END,"Received & AES Decrypted Packet = "+str(aes_decrypt.decode()))
                
    newthread = SimulationThread(message, ecc_sign, zkp_sign, aes_data,text,canvas,line1,line2,x1,y1,x2,y2,x3,y3) 
    newthread.start()

def generateKeys():
    global zkp_proof
    text.delete('1.0', END)
    zkp_proof = ZKProof()
    ECC.generateECCKey()
    text.insert(END,"Private Keys : "+str(ECC.private_key)+"\n")
    text.insert(END,"Public Keys : "+str(ECC.public_key)+"\n\n")
    
def generateIOTNetwork():
    global mobile
    global labels
    global mobile_x
    global mobile_y
    global source_list, dest_list
    mobile = []
    mobile_x = []
    mobile_y = []
    labels = []
    canvas.update()

    x = 5
    y = 350
    mobile_x.append(x)
    mobile_y.append(y)
    name = canvas.create_oval(x,y,x+40,y+40, fill="blue")
    lbl = canvas.create_text(x+20,y-10,fill="darkblue",font="Times 7 italic bold",text="Hospital")
    labels.append(lbl)
    mobile.append(name)
    rewards.append(0)
    for i in range(1,20):
        run = True
        while run == True:
            x = random.randint(100, 450)
            y = random.randint(50, 600)
            flag = getDistance(mobile_x,mobile_y,x,y)
            if flag == False:
                rewards.append(0)
                mobile_x.append(x)
                mobile_y.append(y)
                run = False
                name = canvas.create_oval(x,y,x+40,y+40, fill="red")
                lbl = canvas.create_text(x+20,y-10,fill="darkblue",font="Times 8 italic bold",text="P"+str(i))
                labels.append(lbl)
                mobile.append(name)    

def startSimulation():
    global option
    global line1,line2,line3, details
    global source_list, dest_list, ecc, zkp, zkp_proof
    text.delete('1.0', END)
    src = int(source_list.get())
    dest = 0
    start1 = timeit.default_timer()
    text.insert(END,"Selected Patient Sensor is : "+str(src)+"\n")
    if option == 1:
        canvas.delete(line1)
        canvas.delete(line2)
        canvas.update()
    src_x = mobile_x[src]
    src_y = mobile_y[src]
    des_x = mobile_x[dest]
    des_y = mobile_y[dest]
    distance = 10000
    distance1 = 10000
    hop = -1
    neighbours = []
    for i in range(1,20):
        temp_x = mobile_x[i]
        temp_y = mobile_y[i]
        if i != src and i != dest:
            dist1 = math.sqrt((src_x - temp_x)*2 + (src_y - temp_y)*2)
            if dist1 < distance:
                distance = dist1
                neighbours.append(i)
    for i in range(len(neighbours)):
        nei = neighbours[i]
        temp_x = mobile_x[nei]
        temp_y = mobile_y[nei]
        dist1 = math.sqrt((des_x - temp_x)*2 + (des_y - temp_y)*2)
        if dist1 < distance1:
            distance1 = dist1
            hop = nei                
    if hop != -1:
        hop = hop + 1
        bp = random.randint(60, 150)
        heart = random.randint(30, 90)
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        message = "P"+str(src)+" BP="+str(bp)+" Heart="+str(heart)+" "+dt_string
        start_time = timeit.default_timer()
        ecc_sign = ECC.eccSign(message.encode())
        aes_data = encryptAES(message)
        end_time = timeit.default_timer()
        ecc_time = end_time - start_time
        ecc.append(ecc_time)
        start_time = timeit.default_timer()
        zkp_sign = zkp_proof.generate_proof(message)
        end_time = timeit.default_timer()
        zkp_time = end_time - start_time
        zkp.append(zkp_time)
        readDetails()
        saveDataBlockChain(message+"\n")
        text.insert(END,"Sending Packet : "+message+"\n")
        text.insert(END,"ECC Signature : "+str(ecc_sign)+"\n")
        text.insert(END,"ZKP Signature : "+str(zkp_sign)+"\n")
        text.insert(END,"AES Encrypted Data : "+str(aes_data)+"\n\n")
        line1 = canvas.create_line(mobile_x[src]+20, mobile_y[src]+20,mobile_x[hop]+20, mobile_y[hop]+20,fill='black',width=3)
        line2 = canvas.create_line(mobile_x[hop]+20, mobile_y[hop]+20,mobile_x[dest]+20, mobile_y[dest]+20,fill='black',width=3)
        startDataTransferSimulation(message, ecc_sign, zkp_sign, aes_data, text,canvas,line1,line2,(mobile_x[src]+20),(mobile_y[src]+20),(mobile_x[hop]+20),(mobile_y[hop]+20),(mobile_x[dest]+20),(mobile_y[dest]+20))
        option = 1
    else:
        text.insert(END,"Unable to report data to Publisher. Try another participant\n")

def graph():
    global zkp, ecc
    plt.figure(figsize=(10,6))
    plt.grid(True)
    plt.xlabel('Number of Verifications')
    plt.ylabel('Running Time')
    plt.plot(ecc, 'ro-', color = 'green')
    plt.plot(zkp, 'ro-', color = 'blue')
    plt.legend(['ECC Verification', 'ZKP Verification'], loc='upper left')
    plt.title('Algorithms Running Time Graph')
    plt.show()
    z
def readPatientData():
    global details
    output = '<table border=1 align=center>'
    output+='<tr><th><font size=3 color=black>Patient ID</font></th>'
    output+='<th><font size=3 color=black>Blood Pressure</font></th>'
    output+='<th><font size=3 color=black>Heart Rate</font></th>'
    output+='<th><font size=3 color=black>Date</font></th>'
    output+='<th><font size=3 color=black>Time</font></th></tr>'
    readDetails()
    arr = details.split("\n")
    for i in range(len(arr)-1):
        values = arr[i].split(" ")
        output+='<tr><td><font size=3 color=black>'+values[0]+'</font></td>'
        output+='<td><font size=3 color=black>'+values[1]+'</font></td>'
        output+='<td><font size=3 color=black>'+values[2]+'</font></td>'
        output+='<td><font size=3 color=black>'+values[3]+'</font></td>'
        output+='<td><font size=3 color=black>'+values[4]+'</font></td></tr>'
    output += "</table><br/><br/><br/><br/>"
    f = open("output.html", "w")
    f.write(output)
    f.close()
    webbrowser.open("output.html",new=1)   
        

def Main():
    global root
    global tf1
    global text
    global canvas
    global source_list, dest_list, tf1
    root = tkinter.Tk()
    root.geometry("1300x1200")
    root.title("Blockchain for the Management of Internet of Things Devices in the Medical Industry")
    root.resizable(True,True)
    font1 = ('times', 12, 'bold')

    canvas = Canvas(root, width = 800, height = 700)
    canvas.pack()

    l1 = Label(root, text='IOT Sensor ID:')
    l1.config(font=font1)
    l1.place(x=820,y=10)

    mid = []
    for i in range(1,20):
        mid.append(str(i))
    source_list = ttk.Combobox(root,values=mid,postcommand=lambda: source_list.configure(values=mid))
    source_list.place(x=970,y=10)
    source_list.current(0)
    source_list.config(font=font1)

    createButton = Button(root, text="Generate Medical IOT Sensors", command=generateIOTNetwork)
    createButton.place(x=820,y=60)
    createButton.config(font=font1)

    keysButton = Button(root, text="Generate Private & Public Keys", command=generateKeys)
    keysButton.place(x=820,y=110)
    keysButton.config(font=font1)

    startButton = Button(root, text="Start Simulation", command=startSimulation)
    startButton.place(x=820,y=160)
    startButton.config(font=font1)

    graphButton = Button(root, text="Verification Time Chart", command=graph)
    graphButton.place(x=820,y=210)
    graphButton.config(font=font1)

    readButton = Button(root, text="Read Data from Blockchain", command=readPatientData)
    readButton.place(x=820,y=260)
    readButton.config(font=font1)

    text=Text(root,height=25,width=70)
    scroll=Scrollbar(text)
    text.configure(yscrollcommand=scroll.set)
    text.place(x=800,y=310)
    
    
    root.mainloop()
   
 
if _name== 'main_' :
    Main ()