# xble
pwnagotchi BLE plugin

## Why

I liked the idea of the pwnagotchi being happy or sad based on its environment but not the covert malicious use of deauthing WiFi networks.  I've been wanting to learn more about Bluetooth Low Energy (BLE) and the creater of `bettercap` that I was using to scan BLE networks is the same creator of the `pwnagotchi` project.

## What

This plugin simply uses bettercap on a 30s loop to capture all new BLE devices it sees.  They are logged to a file under the handshakes directory in JSON format for whatever use someone might want to use that data for. 

My original plan was to create a small ESP32 based device that could log whenever it sees any RF signals from Flock Security devices to later be uploaded to [https://deflock.me](Deflock.me).  This is less successful than I wanted, mainly because I was unable to see any signals from the devices.  I needed a better scanner.  This is why I ran across `bettercap`.

## Use

Simply add the plug into your custom-plugins directory.  You will see what the BLE plugin is doing under the section that displays the pwnagotchi's emotion.  Under that you'll see the name of the last device seen.  Additionally next to a section labeled "XBLE" you will see how many BLE devices seen in the last five minutes and how many of them are named device.

## Caveats

It appears that bluetooth devices rotate their mac addresses for additional privacy in 15 minute intervals.  A stationary pwnagotchi could be used to track those rotations based on signal strength but I have no way of knowing if the person is moving with their device or not.  I don't see any benefit to tracking devices like this either so I haven't followed up on the idea.
