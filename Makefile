APXS=apxs
SOURCE= \
  mod_authn_totp.c \
  include/hmac.c \
  include/sha1.c

.PHONY: all
all: $(SOURCE)
	$(APXS) -I./include -c $^

install: all
	sudo $(APXS) -i -a -n "authn_totp" mod_authn_totp.la

test: install
	sudo apache2ctl restart

clean:
	rm -rf .libs/ *.o *.so *.la *.slo *.lo
