
/* Includes */

#include "uart_queue.h"

/* Defines */

#define  UART_QUEUE_BUFFER_SIZE  300

/* Variables */

// UART Queue for COM
uint8_t  uart_queue_com_buffer[UART_QUEUE_BUFFER_SIZE];
uint32_t  uart_queue_com_point_head = 0;
uint32_t  uart_queue_com_point_tail = 0;

// UART Queue for Serial Debug

/* Static Functions */

static void uart_queue_increase_point_value(uint32_t * data_p)
{
    (* data_p) ++;
    if(UART_QUEUE_BUFFER_SIZE == (* data_p))
    {
        (* data_p) = 0;
    }
}

/* Global Functions */

void UartQueue_Initialize(void)
{
    uart_queue_com_point_head = uart_queue_com_point_tail = 0;
}

// UART Queue for COM

uint8_t UartQueue_COM_Is_Empty(void)
{
    if(uart_queue_com_point_head == uart_queue_com_point_tail)
    {
        return 1;
    }
    return 0;
}

void UartQueue_COM_EnQueue(uint8_t data)
{
    uart_queue_com_buffer[uart_queue_com_point_head] = data;
    uart_queue_increase_point_value(&uart_queue_com_point_head);
}

uint16_t UartQueue_COM_DeQueue(void)
{
    uint16_t retVal = uart_queue_com_buffer[uart_queue_com_point_tail];
    uart_queue_increase_point_value(&uart_queue_com_point_tail);
    return retVal;
}

