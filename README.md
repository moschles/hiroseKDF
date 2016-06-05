# hiroseKDF
Key Derivation Function using a One-Way Cryptographic Compression Function

HiroseKDF is written as a class for easy deployment.

It accepts a message of any length up to 536 Megabytes and returns a digest of 256 bits.
The hash function will accept messages whose length is specified at bit-level precision.
When hashing binary data, the supplied length must be given in BITS, not bytes. 
The hash function is derived from a one-way cryptographic compression function.

The OWCC function is described mathematically in the paper titled, 

  "How to Construct Double-Block-Length Hash Functions"  
    	by Shoichi Hirose , (University of Fukui)
    	
