# tea
Common Lisp XXTEA encryption library.

## Usage
The key is a list of 4 (UNSIGNED-BYTE 32) integers. Encrypt/decrypt a 
sequence of octets (the sequence must have a length a multiple of 4) using 
ENCRYPT and DECRYPT functions. These modify the contents of the input
sequence and are replaced with the ciphertext/plaintext.

## Functions
* ENCRYPT KEY PLAINTEXT ::= replace plaintext with ciphertext
* DECRYPT KEY CIPHERTEXT ::= replace ciphertext with plaintext
* GENERATE-KEY ::= generate random key 
* KEY-OCTETS ::= convert key to 16 octets
* OCTETS-KEY ::= convert 16 octets to key

## Example

```
CL-USER> (defvar *key* '(1 2 3 4))
CL-USER> (defvar *v* #(1 1 1 1 1 1 1 1))
CL-USER> (tea:encrypt *key* *v*)
#(164 133 81 22 30 117 209 146)
CL-USER> *v*
#(164 133 81 22 30 117 209 146)
CL-USER> (tea:decrypt *key* *v*)
#(1 1 1 1 1 1 1 1)
CL-USER> *v*
#(1 1 1 1 1 1 1 1)
```

## License
Licensed under the terms of the MIT license.

Frank James 
November 2015.

