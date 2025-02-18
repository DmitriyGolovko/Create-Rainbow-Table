This file will take in a list of passwords seperated by a new line character
and output in csv format: The hash, the password, and the algorithm.

To compile the file remember to use the -lcrypto flag with gcc to compile
and install libssl-dev by the command:

  sudo apt-get install libssl-dev

To get the appropriate libraries.


This program once compiled will have 1 required option and 4 optional. Use
-h in order to get a reference of these options:

-f (file) is the input for the password list.

-o (file) is the optional output file in csv format. Default is stdout.

-v (hash) is an identifier for the hash algorithm. Default is SHA2-256.

-a is to append data to files. Useful if you want to have multiple algorithms in one table.
   The default behavior is to rewrite the files.
   
-l (lines) will specifiy how many lines to read. Default is INT_MAX.
