RPCGEN=rpcgen -M
RPCGEN_SRC=shibrpc.x

all:
clean:

very-clean: 
	$(RM) shibrpc.h shibrpc-xdr.c shibrpc-clnt.c shibrpc-svc.c

rpcgen:
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc.h RPCGEN_ARGS=-h
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-xdr.c RPCGEN_ARGS=-c
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-clnt.c RPCGEN_ARGS=-l
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-svc.c RPCGEN_ARGS=-m
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-server-stubs.c RPCGEN_ARGS=-Ss

do_rpcgen:
	$(RM) $(RPCGEN_TARGET)
	$(RPCGEN) $(RPCGEN_ARGS) -o $(RPCGEN_TARGET) $(RPCGEN_SRC)
