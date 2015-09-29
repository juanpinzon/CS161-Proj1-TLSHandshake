Juan Pinzon  - SID: 23632316 Section: 104 TA: Arjun

1. All messages in this protocol have a type field sent in plaintext. If an attacker can alter packets being sent to and from the server, explain how it can launch a DoS attack on the server or client in a way that does not reveal it’s involvement.
    
    An attacker could intercept every packet to the server and change the type field of every struct to CLIENT_HELLO. This would effectively halt the progress of the handshake and in addition, cause the server to believe that multiple handshakes are being attempted. The server would not know that it is under attack since it is just receiving multiple hello messages which indicate handshake attempt.

2. Look at the function random int(). How are the ”random” numbers chosen? Can an attacker learn any information about our system or other random values if they know our method? Suggest a way that a man-in-the-middle might be able to use this to break our encryption. Tip: try printing random values as they are chosen during the handshake.

    The random numbers are chosen using the time as a seed. If the attacker knows this, he can find the time of our system and using it as a seed, predict our random values. A man in the middle would be able to break the system by obtaining the server and client random number from the client and server hello packets since they are not encrypted. He could also figure out the time that the client_hello message was sent which is the seed for generating random numbers. If he knows the seed then he can figure out the premaster secret which is generated using that seed. Knowing both server and client random numbers along with the premaster secret will allow him to find the master secret and break our handshake encrypting the master scret using SHA256

3. We have talked about a downgrade attack in class before. Assuming that the server and client supported multiple cipher suites (some weaker than others), show how a downgrade attack might be possible on the Terribly Lacking Security handshake. Then suggest a method or adaptation to the handshake that would mitigate a downgrade attack.

    A man in the middle could intercept the client hello message and alter the cipher_suite field to have TLS ciphers in opposite order of preference such that the weakest cipher is most preferred. A method to mitigate a downgrade attack would be to support only the strongest ciphers though that would be inconvenient.

4. (Extra Credit) List as many security flaws in the Terribly Lacking Security protocol/implementation as you can find and suggest ways that you might fix them. (Note: The flaws discussed above do not count)
- Attacker could perform a TCP data injection. Due the fact attacker knows sequence number and can get the ports, Attacker can inject data into the TCP connecntion. 
- Also note that the connection can be terminated by forging a RST packet.
- Another kind of attack could be a "Replay attack", where the attacker send the password of one of the parties from the last session, so the other party accepts thus granting acces to attacker. We can use nonces for preventing replay attacks.