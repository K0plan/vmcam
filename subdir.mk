################################################################################
# 
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
./ssl-client.c \
./vm_api.c \
./tcp-client.c 

OBJS += \
./build/ssl-client.o \
./build/vm_api.o \
./build/tcp-client.o 

C_DEPS += \
./build/ssl-client.d \
./build/vm_api.d \
./build/tcp-client.d 


# Each subdirectory must supply rules for building sources it contributes
build/%.o: ./%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


