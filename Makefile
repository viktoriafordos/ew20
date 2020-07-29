
all:
	build

build: referl
	cp refusr_security.erl referl/lib/referl_user/src/
	cd referl && bin/referl -no_cpp -build tool

referl:
	wget https://plc.inf.elte.hu/erlang/dl/refactorerl-0.9.15.04_updated.tar.gz
	tar -xzf refactorerl-0.9.15.04_updated.tar.gz
	mv refactorerl-0.9.15.04_updated referl

start:
	cd referl && bin/referl

clean:
	rm -rf referl
	rm -rf refactorerl-0.9.15.04_updated.tar.gz
