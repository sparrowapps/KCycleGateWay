# KCyleGateWay

## 라즈베리파이 라이트버젼 설치
2017-07-05-raspbian-jessie-lite.img

이미지 다운로드

<https://downloads.raspberrypi.org/raspbian_lite_latest>

SD 카드 포멧

<https://www.sdcard.org/downloads/formatter_4/>

 Mac 설치 Etcher 설치
 
<https://etcher.io>

### ssh 활성
최신버젼에 jessie-lite를 받아서 메모리카드에 설치 하고 부팅 하면 ssh가 비활성이다.

boot를 마운트 해서

윈도우
~~~
 echo > ssh
~~~
linux / mac
~~~
 touch ssh
~~~
를 하여 ssh 파일이 생성되면 ssh가 enable된다.


### 시리얼 활성
cmdline.txt
~~~
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait
~~~

config.txt

하단에 
~~~
enable_uart=1
~~~
추가

## file system 확장
~~~
sudo rasp-config
~~~

Advanced Options --> A1 Expand Filesystem

reboot


확인
~~~
pi@raspberrypi:~ $ df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/root       7.3G  1.3G  5.7G  19% /
devtmpfs        458M     0  458M   0% /dev
tmpfs           462M     0  462M   0% /dev/shm
tmpfs           462M  6.6M  456M   2% /run
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           462M     0  462M   0% /sys/fs/cgroup
/dev/mmcblk0p1   42M   21M   21M  51% /boot
~~~

## git 설치
~~~
sudo apt-get install git
~~~

## wiringPi 설치
~~~
sudo apt-get install wiringPi
gpio -v
gpio version: 2.44
~~~

또는 직접 빌드
~~~
git clone git://git.drogon.net/wiringPi
cd wiringPi/
./build
~~~

## openssl 설치
~~~
git clone https://github.com/openssl/openssl.git
cd openssl
./config --prefix=/usr --openssldir=/usr/local/openssl shared
make
sudo make install
openssl version
~~~

## 삼바 설치 및 설정
~~~
sudo apt-get install samba samba-common-bin
sudo smbpasswd -a pi
~~~

/etc/samba/smb.conf 편집
~~~
[pi]
path = /home/pi
comment = PI SAMBA SERVER
valid user = pi
writable = yes
browseable = yes
create mask = 0777
public = yes
~~~

### 삼바 재시작
~~~
sudo /etc/init.d/samba restart
~~~



## jansson 설치
~~~
sudo apt-get install libjansson-dev
sudo ldconfig
~~~


## 디버거 nemiver GDB frontend
~~~
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install nemiver    
~~~

## vscode
vs code로 개발

## build & run
~~~
git clone https://github.com/sparrowapps/KCycleGateWay.git
cd KCycleGateWay/KCycleGateWay/build
make clean; make
./KCycleGateWay
~~~
