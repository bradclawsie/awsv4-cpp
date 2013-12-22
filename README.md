awsv4-cpp
=========

A c++11 implementation of awsv4 signature version 4 signing process

For more information on this process, please see 

    http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

This library will produce the "signature" that can be used to complete other 
authorized requests for AWS.

This library uses `openssl`, `Poco` and `boost`. I developed this on debian unstable.

Unfortunately I don't know how these dependencies will be available on non-debian
systems, so please tune the `Makefile` as you see fit.

The `main.cpp` is a basic test suite that uses the sample data available at 

    http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

and produces the output as shown in the AWS docs. Each AWS service seems
to have its own unique needs with regard to authorization - I hope to 
add more to this library over time and make it more useful for specific 
services.
