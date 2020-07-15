# R-Locker


R-Locker is an anti-ransomware tool for Windows platforms. It is built on the Win32 programming interface, so it runs on the user's space without any additional support on kernel mode.

The anti-malware solution is based on the deployment of honeyfiles around the filesystem. A honeyfile works like a trap to block any process trying to read this special type of files. For that, R-Locker is composed of three functional elements: a central FIFO (or named pipe), a set of symbolic links to it, and a monitoring process acting like a FIFO server. 

The central component of the approach is an empty FIFO configured for synchronous communications (WAIT_PIPE flag activated). The symbolic links act like bridges between files namespace and devices namespace (in Windows, named pipes are devices instead of special files). As symbolic links may have extensions, R-Locker use extensions like .pdf, .jpg, .doc,... to make appealing the symbolic links. On the other hand, symbolic links have a size of zero bytes, which makes scalable to deploy enough links around the whole target filesystem to protect the stored information. Once the honeyfiles are deployed the trap is ready, so that as soon as a process reads a trap file, it is blocked by the OS. At this moment, the monitoring module of R-Locker will notify user about the incident to give her the possibility of killing the supossedly malicious instance.

Nowadays, ransomware can be multithreaded to make encryption more efficient. To defeat this kind of malware, R-Locker is also multithreaded so that every monitoring thread is connected to an instance of the FIFO to catch a ransomware thread.

