# BMV2_PATH=/home/bmv2
# P4C=/home/p4c/build/p4c-bm2-ss
# P4C=/home/p4c-bm/p4c_bm/__main__.py
# SWITCH_PATH=$(BMV2_PATH)/targets/simple_switch/simple_switch
# CLI_PATH=$(BMV2_PATH)/tools/runtime_CLI.py


BMV2_SWITCH_EXE = simple_switch_grpc

# include ../utils/Makefile

# START MAKEFILE INCLUDED

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt

ifndef RUN_SCRIPT
RUN_SCRIPT = utils/run.py
endif

ifndef TOPO
TOPO = config/topology.json
endif

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)

ifndef DEFAULT_PROG
DEFAULT_PROG = $(wildcard *.p4)
endif
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(DEFAULT_JSON)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

run: build
	sudo python -E $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo mn -c

build: dirs $(compiled_json)

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

# END MAKEFILE INCLUDED


# run-%: %.json
# 	$(BMV2_SWITCH_EXE) $^ \
# 	-i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 --log-console
#
# config-%: %.json
# 	$(CLI_PATH) --json $^ < $@.txt
#
# %.json : p4src/%.p4
# 	$(P4C) --p4-16 -o $@ $^
#
# kill:
# 	pkill lt-simple_sw
#
# clean:
# 	rm *.json