# KCyleGateWay

## 라즈베리파이 라이트버젼 설치
2017-07-05-raspbian-jessie-lite.img
### ssh 활성
최신버젼에 jessie-lite를 받아서 메모리카드에 설치 하고 부팅 하면 ssh가 비활성이다.
boot를 마운트 해서
윈도우 echo > ssh
linuex / mac touch ssh
를 하여 ssh 파일이 생성되면 ssh가 enable된다.

### 시리얼 활성
cmdline.txt
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait

config.txt
하단에 
enable_uart=1 
추가

## git 설치
sudo apt-get install git

## wiringPi 설치
sudo apt-get install wiringPi
gpio -v
gpio version: 2.44
또는 직접 빌드
git clone git://git.drogon.net/wiringPi
cd wiringPi/
./build


## openssl 설치
git clone https://github.com/openssl/openssl.git
cd openssl
./config --prefix=/usr --openssldir=/usr/local/openssl shared
make
sudo make install
openssl version

## 삼바 설치 및 설정
sudo apt-get install samba samba-common-bin
sudo smbpasswd -a pi

/etc/samba/smb.conf 편집
[pi]
path = /home/pi
comment = PI SAMBA SERVER
valid user = pi
writable = yes
browseable = yes
create mask = 0777
public = yes

삼바 재시작
sudo /etc/init.d/samba restart


## 디버거
sudo apt-get install nemiver	

## vscode
vs code로 개발

