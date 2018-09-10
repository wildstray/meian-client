# meian-client
Shenzhen Meian Technology / Focus burglar alarm TCP client

Shenzhen Meian Technology products are widely known and marketed low cost safety alarm systems. 
Sold all around the world with custom OEM brand names and logos (the generic one is Focus, 
anyway I prefer to avoid other brand named cause I don't want to get in trouble with vendors). 

These alarm systems are hybrid wired/wireless (FSK 433/868MHz) systems with GSM/GPRS and TCP/IP.

This systems supports SIA TCP protocol to notice alarms to CMS and can be configured via web interface or mobile app.

Another interesting feature is the home automation (there is a triple relay switch available for this purpose).

There are iOS and Android clients, but firmware, protocols and apps are closed source. There are no API/webservice available 
to arm/disam, configure the alarm system and to interact with home automation.

With a bit reverse engineering and using a demo installation I wrote a python client for Meian proprietary TCP protocol.
I had nothing to do with Meian, simply I wish/need some bindings for home automation so I wrote it. 
Moreover I think that flaws and security issues of the protocol should be known.

If you want to look for Meian/Focus alarms or verify if your safety alarm system is manifactured by Meain, take a look to their
website: [Shenzhen Meian Technology Co. Ltd](http://www.meianalarm.com/en/) 
