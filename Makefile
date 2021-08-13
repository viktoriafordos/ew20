all:
	build

build: referl
	cp refusr_security.erl referl/lib/referl_user/src/
	cd referl && bin/referl -no_cpp -build tool

referl:
	wget https://plc.inf.elte.hu/erlang/dl/refactorerl-0.9.20.08_v2.zip
	unzip refactorerl-0.9.20.08_v2.zip
	mv refactorerl-0.9.20.08_v2 referl

start:
	cd referl && bin/referl

start-nif:
	cd referl && bin/referl -db nif

clean:
	rm -rf referl
	rm -rf refactorerl-0.9.20.08_v2.zip
