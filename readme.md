# Bignum Dumper

Is an IDA plugin with dual purpose.

* Assisting with dumping of big integers from IDA database.
* Find relations between the acquired integers.

## Assisting with dumping of big integers from IDA database.

_Note: When I write a (big) integer I mean a number of unlimited size, aka bignum._

There are many ways how to store an integer in the computer memory. Usually the integers are stored as an _array_ of _words_.

#### arrays
The arrays can have fixed length or the length is written somewhere else in the memory.
One also has to know the order of words, whether the most significatn word is first or last.

#### words
A word is a sequence of bytes. This plugin supports 1,2,4,8 byte words. But any other length can be programmed in easily.
Also here it is necessary to know the order of bytes in the word.

For more details about this see any modern textbook about computer algebra or read a manual for GMP.

Sometimes integers are stored in textual form in some base. Supported basis are binar, octal, decimal, hexadecimal, base64, and bitcoin base58. For these, the word size is always one.



## Find relations between the acquired integers.
By a relation I mean a formula that is satisfied if the acquired numbers are fed into it.

* a + b = c is satisfied when a=0, b=0, c=0, this is not that interesting.
* y^2 % n = (x^3 + a x + b)%n is satisfied when [x,y] is a point on Weierstrass elliptic curve with parameters a, b, n.
* (x^e)^d % n = x for all x if (e,n) is RSA public key and (e,d) is RSA private key.

This plugin currently supports basic arithmetic, modular arithmetic and arithmetic over Elliptic curves in Weierstrass, Edwards, or Twisted Edwards form.

Once these relations are discovered some algorithms are run on them.

* There is Wiener's attack for RSA with low private exponent.
* RSA Small prime difference attack
* Factorisation of n once both e and d are known
* Detects of the situation that there are discovered points on elliptic curves, multiplicants and their multiples. (see the Examples section).
* ...

## UI documentation
Run the plugin by selecting menu Edit / Plugins / Bignum Dumper or alt-e,g,b.

### preset
Here you can quickly select one of the predefined configurations.

### address
Write here the memory address of where the integer is located.
You can write any IDC expression. My favourite addresses are: 'here', 'Dword(here+8)'.

### Guess template button
Fill a valid address and press this button if you want the plugin to guess the type of the number at that address.
This is capable of detection all the presets. But beware that sometimes hexadecimal number can look like octal and base64 can look like base58.

### words
Write here the length of the dumped integer in _words_.

### word size
Choose here the desired word size.

### word size
Choose here the base of dumped integer.

### word endian
Choose here the order of bytes in the word.

### bignum endian
Choose here the order of words in the bignum.

### example

This shows how the number one would be stored int the memory for selected combination of options. 

### dump button
Press this button once you are satisfied with your choice of options. The plugin will try to read the memory and insert the dumped integer into the list.

### guess button
This willl start the second part of the plugin. All results are written into IDA console.

### save / load buttons
Use these if you want to save / load the list of dumped integers.

### idc expression button
Press this button if you want the program to generate and IDC command for current configuration.

### numbers
This list contains all the dumped integers in decimal and hexadecimal presentation. Also shows the number of bits of the integer and a whether it is a prime number.
You can use the context menu to add / delete to / from the list.
(You can also filter and sort like in every other IDA chooser.)


## IDC interface
This extends the IDC language with three functions.

    dump(address, length, word_size, base_idx, word_endian, bignum_endian);
    // use this function if you want to dump the integers from breakpoint callback or any other automation of integer dumping
    // usually you won't need to enter arguments for this by hand, the UI will help you with that
    // allowed values for word_endian and bignum_endian are numbers -1 and 1.
    
    BER_int_length(address)
    //tries to interpret data at address as BER encoded integer and returns it's length 
    BER_int_offset(address)
    //tries to interpret data at address as BER encoded integer and the offset to raw integer bytes



## Examples:

samples\elliptic_curve.txt:
This file demonstrates the ability to detect the points at the Weierstrass elliptic curve. Just load this text file in the plugin and click on guess button.
    


samples\encodings.bin:
this simple file just demonstrates the ability to guess and dump the numbers in different bases. 

samples\BER:
File BER.bin contains some BER encoded numbers. 
Script find_all_ber.idc demonstrates how to dump them automatically.

samples\keygenme_3:
samples\Ed_Edd_n_Eddy:
Try to use my plugin to crack these two crackmes from Tamaroth / crackmes.us.

Just find the interesting functions, dump numbers that go in, dump a number that goes out. Guess what the function does and move to another one.

The principle of both crackmes can be revealed in under 30 minutes. Including unpacking of these files. And there is no need to read more than 100 lines of assembler.




_Milan Bohacek, Charles University in Prague_
