#include <wiringPi.h>

// LED �� - wiringPi �� 0�� BCM_GPIO 17�Դϴ�.
// wiringPiSetupSys�� �ʱ�ȭ�� �� BCM ��ȣ �ű�⸦ ����ؾ� �մϴ�.
// �ٸ� PIN ��ȣ�� �����ϴ� ��쿡�� BCM ��ȣ �ű�⸦ ����ϼ���.
// �Ӽ� ������ - ���� �̺�Ʈ - ���� ���� �� �̺�Ʈ ����� ������Ʈ�ϼ���. 
// �� ��ɿ����� wiringPiSetupSys ������ GPIO �������Ⱑ ���˴ϴ�.
#define	LED	17

int main(void)
{
	wiringPiSetupSys();

	pinMode(LED, OUTPUT);

	while (true)
	{
		digitalWrite(LED, HIGH);  // �ѱ�
		delay(500); // ms
		digitalWrite(LED, LOW);	  // ����
		delay(500);
	}
	return 0;
}