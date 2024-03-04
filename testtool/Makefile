SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

Enclave_Include_Paths := -I$(SGX_SDK)/include 


egocmc: 
	CGO_CFLAGS=-D_FORTIFY_SOURCE=0 ego-go build && ego sign testtool

.PHONY: all
all:
	go build
