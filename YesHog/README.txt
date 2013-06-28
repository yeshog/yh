Hola

1. What is YesHog?
   YesHog is a hobby project that has:
   a. A fully working TLS 1.0 stack on x86
   b. A functional (it works albeit being horribly incomplete) networking stack for Atmega128
   c. A l2, l3, l4, l5 all in one framework that is (still) aimed for AVRs but is dreadfully slow (atleast now).
   
2. How do I build YesHog for x86?
   Do the following on your favorite linux distro. Of course make sure you have gcc
      # alias yh='export TOOLCHAIN=x86; export TOPDIR=/home/user/yh/YesHog;cd /home/user/yh/YesHog; export PATH=/home/user/yh/YesHog/bashup:$PATH'
      # yh
      # make

3. How do I build YesHog for AVR (atmega128)?
   Do the following on your favorite linux distro. Of course make sure you have gcc
      # alias ta='export TOOLCHAIN=AVR;export TOPDIR=/home/user/yh/YesHog;cd /home/user/yh/YesHog'
      # yh
      # make

4. Ok it builds, now what does it do?
   Most tests are on x86. So:
   1. yh          ## see 2
   2. cd net
   3. sudo ./test ## this will start the tls 1.0 echo server
   4. openssl s_client -connect 127.0.0.1:443 ## connect to the server and type away and make sure it echoes back
   
5. So whats the status on AVR:
   Right now performance of Elliptic Curve Cipher in Fp is being tested on an atmega128 in my basement. The hope is that some day I can get this within human pain of use threshold.
   If you want to see what it is doing:
   1. ta ## see 3
   2. cd pkcs
   3. make
   4.                   ## burn avr_ecc.hex on the atmega128
   5. Wait for about 82 seconds (while trying to not use the baseball bat) and see that the ECDSA signed certificate is verified.

6. Can I help?
   Hell yes, as you can see the code was meant for 8bit toolchains and can be made MUCH faster on x86 and x86_64.
   Given x86_64 you SECP256R1 curve modulus is 4 * size_t (yumm!)

7. What else is there?
   I do have RSA fully implemeted, but it is not being used because it needs more real estate on the atmega128
   Implementation started with elliptic curve cipher secp160r1 but now secp256r1 is in use.

8. So whats the point of having another tls package?
   1. The package is small and embeddable because it is limited in what it does.
   1. Most of the implementation avoids mallocs and we know the upper bound on the crypto variables, wherever they reside.
   2. Attempt to keep code clean. The code may be case (snake/camel) inconcistent but I tried to keep it clean
   3. printf's can be evil since they take up '.data'. So the way to develop is:
      a. First come up with unique error codes for all possible failures.
      b. Do not shy from a. and never return -1 for just about every failure.
      c. Try to keep it somewhat readable


YN/Seattle



