# FireWrecker
This project allows an user (admin or not) to open or close an specified port in Windows Firewall to itself.
When the user does not have admin privilege, the program is capable of elevating itself and manage firewall anyway, what in my opinion showcases a vulnerability in the system.

The port being open/closed in the project is '1234', but this can be changed in main.cpp.

This was built using CodeBlocks+MingW32 and was previously tested in Windows 7/8/8.1/10.


## Screenshots:
![alt text](https://i.imgur.com/pouBPIo.png)
![alt text](https://i.imgur.com/4Xowmyw.png)
![alt text](https://i.imgur.com/hJYaSz3.png)












### Possible errors and how to fix:
*When building the project, if CodeBlocks point out that 4 libraries are missing:* 
* Right-click in the project, "Build options ..." -> "Linker Settings".
* Change the link libraries directories to where you have CodeBlocks+MingW32 installed. 
