# Mirai Botnet Detection Tool
In October 2016, the Mirai botnet launched a significant distributed denial of service (DDoS) attack on the domain name system provider Dyn, revealing the potential of Internet of Things (IoT) devices to be weaponized in large-scale cyberattacks.
Although DDoS attacks have existed since the early days of the internet, this incident highlighted how IoT devices could be harnessed to form botnets and disrupt major online services. 
The attack on Dyn resulted in widespread outages, temporarily taking down popular platforms like Twitter, Netflix, Spotify, GitHub, Airbnb, and more, underscoring the vulnerabilities in modern internet infrastructure.

## What's Inside?
1) A python tool is developed which identifies Mirai botnet based on the ip address,using machine learned patterns from the ip address earlier identified at attack scenarios,Decision Tree Classifier
   Algorithm  is used for model creation.[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/mirai_python_tool)
2) Smart IoT environment is created by using a flutter app(only works in emulater)[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/mirai_python_tool) and a wifi-enabled esp8266 microcontroller used to control light bulb.[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/iot/miraii)

## Botnet Detection 
The python tool has simple Tkinter framework,the tool is able to
1)provide detailed report on network analysis 
2)able to send Emails upon botnet detection
3)capture live packets incoming and outgoing in a network and analyze it ,this operation is performed at an instance and may require further advanced programming for purpose of continous sniffing in a live environment
4)Checks for already captured network PCAP files for presence of mirai botnet(Mirai presence pcap file is [ given in ](https://github.com/Shegin733/MiraiBotnet/blob/master/mirai_python_tool/MiraiTraffic.pcap)
5) Downloads PDF of network analysis
6)Send state of network to Firebase realtime database
## Simulated IoT Environment
The simulated IoT environment is created by a ESP8266 Microcontroller connected to a light bulb and buzzer,the 
microcontroller is able to recieve commands from app via Firebase realtime database system to turn on and off the bulb , buzzer will be activated  in presence of mirai so as to shut the effected IoT network,the buzzer will
not go off unless and until either the power system to IoT network is shut down or the threat alert from app is being mitigated via Firebase.
## Flutter Mobile App
The Flutter Mobile smart app is build for smart control of light,it's able to send commands to the IoT device so as to control light bulb.The  mobile app has authentication features with registration and login,
the app is able to recieve commands from python tool regarding network status and create alert based on it,on identifying potential threat of Mirai it activates the buzzer alarm and a warning notification is displayed.
