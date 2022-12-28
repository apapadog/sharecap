TOPTARGETS = all clean

SUBDIRS = src test_sharecap libpcap

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

test_sharecap: src
libpcap: src

.PHONY: $(TOPTARGETS) $(SUBDIRS)

