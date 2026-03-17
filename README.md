# CameradarC 
A camera radar written on C, can export results into json, parse xml from nmap(-oX), bruteforce.

# Install

### First install dependencies

```bash
# on fedora
sudo dnf install libxml2-devel json-c-devel libcurl-devel meson nmap

# debian
sudo apt install libxml2-dev libjson-c-dev libcurl4-openssl-dev meson nmap
 
# arch
sudo pacman -S libxml2 json-c curl meson nmap
```

### Then build.
```bash
meson setup build --prefix=/usr
sudo meson install -C build # if you compile first, start with sudo, meson build's a shared object(lib) than binary
```

### Start!
`cam -t 192.168.1.1 -p 554 -b --export-json`

## Arguments

| Name | What doing | Use | Required |
| :---: | :---: | ---:| :---: |
| --target/-t value | Set target ip, only version 4. | cam --target 192.168.1.1 | ✓ |
| --port/-p value-value | Set target port, can set multiple.| cam --target 192.168.1.1 --port 554-560 | ✓ |
| --brute/-b | Enables bruteforce  | cam -t 192.168.1.1 -p 554-560 -b | ✘ |
| --version/-v | Shows version | cam -v | ✘ |
| --verbose/-V | Enable more logs | cam -t 192.168.1.1 -p 554-560 -v | ✘ |
| --export-json | Exports output into JSON, this argument doens't have any shortcut | cam -t 192.168.1.1 -p 554-560 --export-json <FILE>.json | ✘ |
| --nmap/-n | Enables nmap scanning, unstable feature | cam -t 192.168.1.1 -p 554 -n| ✘ |
| --nmap-xml | Enables nmap scanning with xml | cam -t 192.168.1.1 -p 554 --nmap-xml <FILE>.xml | ✘ |
| --fast | Argument for nmap, enables fastest scan (SYN) + add top 100 ports argument | cam -t 192.168.1.1 -p 554 -n --fast | ✘ |
| --include-amb | Includes an 'ambiguous scan' that show 'trash' port in nmap tagged 'open|filtered'| cam -t 192.168.1.1 -p 554 -n --include-amb | ✘ |
| --help/-h | Shows help | cam -h | ✘ |

# Credits
[Github](https://github.com/Ullaakut/cameradar)
