-include ../common.mk

ifeq ($(strip $(PRJ_CROSS)), )
ifeq ($(strip $(VE_OS)), macos)
all:  protobuf_build openssl_build_macos live555_build
else
all:  protobuf_build openssl_build live555_build
endif
else
all:protobuf_build_cross openssl_build_cross live555_build_cross
endif

clean:distclean
distclean: protobuf_clean openssl_clean live555_clean

protobuf_build:
	mkdir -p protobuf/cmake/linux;
	cd protobuf/cmake/linux && cmake -DCMAKE_CXX_FLAGS=-fPIC -DCMAKE_C_FLAGS=-fPIC -Dprotobuf_MSVC_STATIC_RUNTIME=ON -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=$(VE_PATH)/output/$(VE_INSTALL_DIR)/  ../;
	$(MAKE) -C protobuf/cmake/linux;
	$(MAKE) -C protobuf/cmake/linux install;
	if  test -e $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib64/libprotobuf.a; then cp $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib64/*  $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib/; fi;

protobuf_build_cross:
	cd protobuf; chmod +x ./autogen.sh; ./autogen.sh; chmod +x ./configure ; make distclean; ./configure --prefix=$(VE_PATH)/output/host/
	$(MAKE) -C protobuf; 
	$(MAKE) -C protobuf install; 
	cd protobuf; chmod +x ./configure ; make distclean; ./configure --host=$(VE_CROSS_TOOL) CC=$(CC) CXX=$(CPP)  --prefix=$(VE_PATH)/output/$(VE_INSTALL_DIR)/ --with-protoc=$(VE_PATH)/output/host/bin/protoc
	$(MAKE) -C protobuf; 
	$(MAKE) -C protobuf install; 

openssl_build:
	#cd openssl; chmod +x ./config; chmod +x ./util/pod2mantest; chmod +x ./util/point.sh; ./config --prefix=$(VE_PATH)/output/$(VE_INSTALL_DIR)/ -fPIC;
	cd openssl; chmod +x ./config; chmod +x ./util/pod2mantest; chmod +x ./util/point.sh; ./config --prefix=$(VE_PATH)/output/$(VE_INSTALL_DIR)/ shared;
	$(MAKE) -C openssl && $(MAKE) -C openssl install;
	chmod 777 $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib/libssl*;
	chmod 777 $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib/libcrypto*;

openssl_build_macos:
	cd openssl; chmod +x ./Configure; chmod +x ./util/pod2mantest; chmod +x ./util/point.sh; ./Configure darwin64-x86_64-cc --prefix=$(VE_PATH)/output/$(VE_INSTALL_DIR)/ -fPIC;
	$(MAKE) -C openssl && $(MAKE) -C openssl install_sw;

openssl_build_cross:
	cd openssl; chmod +x ./config; chmod +x ./util/pod2mantest; chmod +x ./util/point.sh; ./config --prefix=$(VE_PATH)/output/$(VE_INSTALL_DIR)/ os/compiler:$(VE_CROSS_COMPILER)gcc  -fPIC;
	$(MAKE) -C openssl && $(MAKE) -C openssl install;

live555_build:
	cd live555; chmod +x genMakefiles; ./genMakefiles linux-64bit; 
	$(MAKE) -C live555;
	$(MAKE) -C live555/live555
	cp ./live555/live555/liblive555.so $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib
	
live555_build_cross:
	cd live555; chmod +x genMakefiles; ./genMakefiles armlinux; 
	$(MAKE) -C live555 CROSS_COMPILE=$(VE_CROSS_COMPILER);
	$(MAKE) -C live555/live555
	cp ./live555/live555/liblive555.so $(VE_PATH)/output/$(VE_INSTALL_DIR)/lib

openssl_clean:
	$(MAKE) -C openssl clean

protobuf_clean:
	rm -rf protobuf/cmake/linux/*.*
	
live555_clean:
	$(MAKE) -C live555 clean
	$(MAKE) -C live555/live555 clean
