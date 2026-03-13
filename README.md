# CameradarC 
A camera radar written on C, can export results into json, parse xml from nmap(-oX), bruteforce.

# Install

### First install dependencies

```bash
# on fedora
sudo dnf install lib-xml2-devel json-c-devel libcurl-devel meson nmap

# debian
sudo apt install lib-xml2-dev libjson-c-dev libcurl4-openssl-dev meson nmap
 
# arch
sudo pacman -S libxml2 json-c curl meson nmap
```

### Then build.
```bash
meson setup build
sudo meson install -C build
```

### Start!
`cam -t 192.168.1.1 -p 554 -b --export-json`

## Arguments

| Name | What doing | Use | Required |
| :---: | :---: | ---:| :---: |
| --target/-t value | Set target ip, only version 4. | cam --target 192.168.1.1 | ✓ |
| --port/-p value-value | Set target port, can set multiple.| cam --target 192.168.1.1 --port 554-560 | ✓ |
| --brute/-b | Enables bruteforce  | cam -t 192.168.1.1 -p 554-560 -b | ✘ |
| --verbose/-v | Enable more logs | cam -t 192.168.1.1 -p 554-560 -v | ✘ |
| --export-json | Exports output into JSON | cam -t 192.168.1.1 -p 554-560 --export-json | ✘ |
| --help/-h | Shows help | cam -h | ✘ |

# Credits
[Github](https://github.com/Ullaakut/cameradar)
