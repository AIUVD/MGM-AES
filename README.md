# MGM-AES
A contermeasure against DL-based SCA

Both MGM and XMGM are implemented on the chipWhisper CW303.

MGM.c: The main body of the AES-MGM implementation

The XMGM folder contains three files：

Cipher1.h: head file

Cipher1.S: masked AES encryption function in assembly format

simpleserial-aes.c: Initialization before sampling, including generating random masks
