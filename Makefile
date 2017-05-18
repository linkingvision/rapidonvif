subdirs=3rdparty onvif/onvifagent onvif 

all:
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) $(MFLAGS); fi;) ); done
	strip ./output/$(VE_INSTALL_DIR)/lib/*.so
	
clean:
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) clean; fi;) ); done
	#rm -rf ./linux/*.so ./linux/bin ./linux/lib/ ./linux/share ./linux/ssl ./linux/include

install:
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) install; fi;) ); done

distclean: clean
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) distclean; fi;) ); done
	rm -rf ./output/$(VE_INSTALL_DIR)/ 

	
