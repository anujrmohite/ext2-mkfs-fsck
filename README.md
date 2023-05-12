# userland_os_project_mkfs_fsck

### 1. How to run the Project?
Navigate to the project directory int the terminal and run the command:
```
$ make final
$ sudo ./mkfs2 -b 1024 -d /dev/sdb1
```
Make sure that the executable has the correct permissions to be executed by running the command:
```
$ chmod +x final
```
For fsck:

First compile the program by using command:
```
$ gcc fsck.c -o fsck
```
And then to run this:
```
$ sudo ./fsck -p 1 -d /dev/sdb1 -y
```# OS-mkfs-fsck
