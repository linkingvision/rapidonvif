subdirs=3rdparty onvif 

all:
	chmod +x ./h5ss/*.sh
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) $(MFLAGS); fi;) ); done
	strip ./output/$(VE_INSTALL_DIR)/lib/*.so
	cp -r ./h5ss/*.sh ./output/$(VE_INSTALL_DIR)/
	cp -r ./h5ss/www ./output/$(VE_INSTALL_DIR)/
	cp -r ./h5ss/ssl ./output/$(VE_INSTALL_DIR)/
clean:
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) clean; fi;) ); done
	#rm -rf ./linux/*.so ./linux/bin ./linux/lib/ ./linux/share ./linux/ssl ./linux/include

install:
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) install; fi;) ); done

distclean: clean
	for d in $(subdirs); do (cd $$d; (if  test -e "Makefile"; then $(MAKE) distclean; fi;) ); done
	rm -rf ./output/$(VE_INSTALL_DIR)/ 

	
