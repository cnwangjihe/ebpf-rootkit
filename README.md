# EBPF Rootkit

A simple rootkit written in ebpf.  
  
This project was used by me to practice writing ebpf programs, and many parts were referenced from [TripleCross](https://github.com/h3xduck/TripleCross), [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) and [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap).  
The code is only for research and study use, any illegal use is prohibited, and the consequences will be borne by you.  
Only works on Linux systems with sudo installed.  

### Usage
```
cd src
make
sudo ./rootkit
```

After loading it, you can execute any program as uid 0 using `run_prog_as_root YOUR_PROGRAM`.  
In my test, the rootkit only 100% works on zsh and dash. In bash or fish, you have to use `bash/fish -c "run_prog_as_root XXX"` to achieve a high success rate.  

### Technical Details

I use ebpf tracepoint hook enter_execve, change execve filename from `run_prog_as_root` to `sudo` and save the pid to map.  
At the same time, it hooks enter_read and exit_read. If a program with pid in map, try to read file named `sudoers`, ebpf rootkit will modify read buf content, adding the following lines to it:  
```
User_Alias HARUKA = #UID
HARUKA ALL=(ALL:ALL) NOPASSWD:ALL
```
UID is the current user's uid, ebpf rootkit will fill it dynamically.  
