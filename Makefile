PACKAGE         ?= navstar
VERSION         ?= $(shell git describe --tags)
BASE_DIR         = $(shell pwd)
ERLANG_BIN       = $(shell dirname $(shell which erl))
REBAR            = $(shell pwd)/rebar3

.PHONY: rel deps test eqc

all: compile

##
## Compilation targets
##

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

develop:
	docker build -t ethos-navstar -f Dockerfile.dev .
	docker run -it --rm \
	-v $$PWD:/host \
	-w /host \
	ethos-navstar

##
## Test targets
##

check: test xref dialyzer lint cover edoc

test: ct eunit

lint:
	${REBAR} as lint lint

eqc:
	${REBAR} as test eqc

eunit:
	${REBAR} as test eunit

ct:
	${REBAR} as test ct -v

cover:
	./rebar3 as test cover

edoc:
	./rebar3 edoc

##
## Release targets
##

rel:
	${REBAR} as prod release

stage:
	${REBAR} release -d

shell:
	${REBAR} shell --apps spartan

release:
	$(REBAR) clean
	rm -rf ./_build/*
	${REBAR} as prod tar
	cp -f ./_build/prod/rel/navstar/navstar*.tar.gz ./release/

s3:
	aws s3 cp ./release/navstar*.tar.gz s3://ethos-dcos-binaries/dcos-navstar/ --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
	

DIALYZER_APPS = kernel stdlib erts sasl eunit syntax_tools compiler crypto

include tools.mk
