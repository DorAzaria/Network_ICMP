# Network ICMP and Sniffing

Requirements:
1) myping sends `ICMP ECHO REQUEST` and receives `ICMP-ECHO-REPLY` (one
time is enough)
2) myping calculates the RTT time in milliseconds and microseconds.
<p>&nbsp;</p>
  <img width="600" height="300" src="https://www.layerstack.com/img/docs/resources/pingdiagram2.jpg">
</p>
<p>&nbsp;</p>

* PING (Packet Internet Groper) command is used to check the network connectivity between a source and destination and it use ICMP(Internet Control Message Protocol) to send  echo request messages to the destination and waiting for a response.

* ICMP is part of the Internet protocol suite as defined in RFC 792. ICMP messages are typically used for diagnostic or control purposes or generated in response to errors in IP   operations (as specified in RFC 1122). ICMP errors are directed to the source IP address of the originating packet.

The Internet Control Message Protocol (ICMP) has many messages that are identified by a "type" field, these are defined by RFCs. Many of the types of ICMP message are now obsolete and are no longer seen in the Internet. Some important ones which are widely used include:

| Type | Info |
| ----- | ---- | 
| 0 |  Echo Reply |
| 1 |  Unassigned |
| 2 |  Unassigned  |
| 3 |  Destination Unreachable |
| 4 |  Source Quench |
| 5 |  Redirect |
| 6 |   Alternate Host Address|
| 7 |   Unassigned|
| 8 |   Echo |
| 9 |   Router Advertisement |
| 10 |  Router Selection  |
| 11 | Time Exceeded |

And many more...

## Output Screenshot
![](https://i.ibb.co/SXRmX6N/icmp.png)
