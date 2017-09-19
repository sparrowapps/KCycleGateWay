#ifndef __UART_QUEUE_H
#define __UART_QUEUE_H

/* Includes */

#include "stm32f3xx_hal.h"

/* Exported constants */

/* Exported functions */

void UartQueue_Initialize(void);

// UART Queue for COM

uint8_t UartQueue_COM_Is_Empty(void);
void UartQueue_COM_EnQueue(uint8_t data);
uint16_t UartQueue_COM_DeQueue(void);
#endif /* __UART_QUEUE_H */

