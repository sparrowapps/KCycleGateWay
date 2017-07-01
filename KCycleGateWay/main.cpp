#include <wiringPi.h>

// LED 핀 - wiringPi 핀 0은 BCM_GPIO 17입니다.
// wiringPiSetupSys를 초기화할 때 BCM 번호 매기기를 사용해야 합니다.
// 다른 PIN 번호를 선택하는 경우에도 BCM 번호 매기기를 사용하세요.
// 속성 페이지 - 빌드 이벤트 - 원격 빌드 후 이벤트 명령을 업데이트하세요. 
// 이 명령에서는 wiringPiSetupSys 설정의 GPIO 내보내기가 사용됩니다.
#define	LED	17

int main(void)
{
	wiringPiSetupSys();

	pinMode(LED, OUTPUT);

	while (true)
	{
		digitalWrite(LED, HIGH);  // 켜기
		delay(500); // ms
		digitalWrite(LED, LOW);	  // 끄기
		delay(500);
	}
	return 0;
}