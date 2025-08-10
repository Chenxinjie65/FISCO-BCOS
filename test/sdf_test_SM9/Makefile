# Copyright (c) 2015 C*Core Technologies Co., LTD.
# Author: goo

#Set Driver Type
RM := rm -rf

TARGET := sdftest

DIRS := ./

SOURCES := $(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))

OBJS := $(notdir $(SOURCES:.c=.o))
OBJ_PATH := ./objs/
OBJS_O := $(addprefix $(OBJ_PATH), $(OBJS))
OBJS_D := $(OBJS_O:.o=.d)

CC := gcc
LIBSKF :=  

LIBS := -lpthread -lsdf_crypto -lrt
LIBPATH := -L./

INCLUDE:= -I./

CFLAGS := $(SYMBOL) $(INCLUDE) -O3 -Wall -fmessage-length=0 -fPIC -MMD -MP -g

vpath =

.PHONY: all clean

all: $(OBJ_PATH) $(TARGET)

$(OBJ_PATH):	
	mkdir -p ./$@

$(TARGET): $(OBJS_O)	
	@echo 'Linking......'	
	$(CC) -o $@ $^ $(LIBS) $(LIBPATH)	
	@echo 'Finished Linking: $@'	
	@echo ' '

$(OBJS_O): $(SOURCES)	
	@echo 'Building file: $(filter %$(*F).c,$(SOURCES))'	
	$(CC) $(CFLAGS) -o $@ -c $(filter %$(*F).c,$(SOURCES))	
	@echo 'Finished building: $@'	
	@echo ' '

clean:	
	-$(RM) $(OBJS_O) $(OBJS_D) $(TARGET)	
	-@echo ' '

