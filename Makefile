APXS=apxs
SOURCE= \
  mod_totp_authenticator.c \
  utils.c \
  include/hmac.c \
  include/sha1.c 

.PHONY: all
all: $(SOURCE)
	$(APXS) -I./include -c $^

install: all
	sudo cp .libs/mod_totp_authenticator.so /usr/lib/apache2/modules/

clean:
	rm -rf .libs/ *.o *.so *.la *.slo *.lo

test:
	make install
	sleep 1
	sudo service httpd restart
	
