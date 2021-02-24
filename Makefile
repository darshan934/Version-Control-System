SUBDIRS := server client tests
.PHONY: all clean  $(SUBDIRS)

all clean:
	for dir in $(SUBDIRS); do \
	    $(MAKE) -C $$dir -f Makefile $@; \
	  done
$(SUBDIRS):
	$(MAKE) -C $@

