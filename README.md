# SNIFFIT
**Historical packet sniffer and monitoring tool**


<br><br>
**1. HELP THIS PROJECT**<br>
**2. I AND SNIFFIT**<br>
**2. WHAT IS AXEL?**<br>
**3. BUILDING FROM SOURCE**<br>
**4. LICENSE**<br>



--------------------
1. HELP THIS PROJECT
--------------------

Sniffit needs your help. **If you are a programmer** and if you wants to
help a nice project, this is your opportunity.

My name is Eriberto and **I am not a C developer**. I imported Sniffit from
Internet to GitHub (the original homepage and developer are inactive).
After this, I applied all patches found in Debian project and other
places for this program. All my initial work was registered in CHANGELOG
file (version 0.4.0 and later releases). I also maintain Sniffit packaged
in Debian[1].

If you are interested to help Axel, read the [CONTRIBUTING.md](CONTRIBUTING.md) file.

[1] https://packages.qa.debian.org/s/sniffit.html<br>


----------------
2. I AND SNIFFIT
----------------

Well, sniffit is a very old packet sniffer, originally developed by
Brecht Claerhout, between 1996 and 1998. This was the first program
that I compiled in GNU/Linux (in 1997). So, I have a special fondness for
this program. So, since 2015 I have maintained it as a package in Debian.
Since November 2016 I am trying to maintain it in GitHub but I need help!
Please, help this project (see above how to do it).


-------------------
3. WHAT IS SNIFFIT?
-------------------

sniffit is a packet sniffer for TCP/UDP/ICMP packets over IPv4. It is able
to give you a very detailed technical info on these packets, as SEQ, ACK, TTL,
Window, etc. The packet contents also can be viewed, in different formats
(hex or plain text, etc.).


-----------------------
4. BUILDING FROM SOURCE
-----------------------

Run `./autogen.sh` to create the configure script, then run
./configure, make and make install.

This program depends of the libpcap and libncurses.


----------
5. LICENSE
----------

Sniffit is under BSD-3-Clause license.
