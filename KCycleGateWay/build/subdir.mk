# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../main.c \
../message_queue.c \
../micomd.c \
../ssltest.c \
../uart.c \
../base64.c

OBJS += \
./main.o \
./message_queue.o \
./micomd.o \
./ssltest.o \
./uart.o \
./base64.o

C_DEPS += \
./main.d \
./message_queue.d \
./micomd.d \
./ssltest.d \
./uart.d \
./base64.d

# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	
	gcc -I"../include" -O0 -g3  -c -fpermissive -std=c11 -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


