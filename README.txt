Distritubed Secure Channel README
========================================

NOTICE
----------------------------------------

The application has been extensively testing on the latest version of Ubuntu 
Linux, but should also work under Windows. Due to the firewall restrictions on 
Windows and Linux it is easiest to test the use of the application on the same 
machine by simply running two separate instances of the application.


EXECUTION FROM SOURCE FILES
----------------------------------------

The application can be executed directly from source files by opening the
existing project in eclipse. The project file is located in the root of the
Source Code/ directory. After importing the project in eclipse all of the 
library JAR files in the lib/ directory must be added to the build path, the
application may not execute at all or have unexecpected results if executed
without having all of the necessary libraries added to the build path.

A much easier solution is to execute the included JAR file, see below for
instructions.


EXECUTION FROM JAR FILE
----------------------------------------

The appliation can easily be executed by simply running the included JAR file
located in the bin/ sub-directory of the Source Code/ directory. The JAR file
must be executed from the command line as the application is a terminal based
IRC client.

The application can be executed by navigating to the bin/ directory in the
terminal and executing the JAR file using the following terminal command.


    java -jar SecureChannel.jar



