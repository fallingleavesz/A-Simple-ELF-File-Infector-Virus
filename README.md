# A Simple ELF File Infector Virus

**Intro**

A simple Linux virus that infects one Linux ELF executable at a time in the directory that it is started in while maintaining the original functionality of the host application.



Structure of the ELF file before being infected

```
+-----------------+
|                 |
| ELF Executable  |
|                 |
+-----------------+
```

Structure of the ELF file after being infected

```
+-----------------+
|Virus Itself(ELF)|
+-----------------+
|Virus Signature  |
+-----------------+
|                 |
| Original ELF    |
| Executable      |
|                 |
+-----------------+
```

</br>


**Technical Overview**

When the infected ELF executable runs, it first activates the virus code, which is an ELF file itself positioned at the start and is itself an ELF file. The virus then executes its payload (printing the message `Hello! I am a simple virus!` as a benign demonstration), and then seeks out another ELF file to infect. 

Subsequently, the virus identifies the original ELF executable within it. It is feasible because the lengths of both the virus ELF and signature are fixed. After pinpointing the original executable, the virus forwards any arguments it received to this executable and launches it, thereby maintaining the host program's intended functionality.


</br>

**Virus Activity Breakdown**

- Payload Execution
  1. Print the message `Hello! I am a simple virus!` to demonstrate the virus's presence.

- Infection Mechanism
  1. Check if a file is an ELF executable by comparing the magic bytes.
  2. Determine whether the ELF file has already been infected by looking for the virus signature.
  3. Check if the file is write or read protected.
  4. Prepend the virus code and signature to the start of an uninfected ELF file.

- Preserving Host Functionality
  1. Extract and execute the original ELF executable, passing along any command-line arguments it received.



