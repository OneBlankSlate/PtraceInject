LOCAL_PATH := $(call my-dir)  
  
include $(CLEAR_VARS)  
LOCAL_MODULE := injector   
LOCAL_SRC_FILES := ptraceinject.c
  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  
  
include $(BUILD_EXECUTABLE)  