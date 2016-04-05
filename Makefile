get_tls_ticket_key_name:
	gcc -lssl -lcrypto -Wall -O2 $@.c -o $@

all: clean get_tls_ticket_key_name

clean:
	rm -f get_tls_ticket_key_name

.PHONY: all clean

