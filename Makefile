SUBDIRS = src

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
install:
	sudo bash -x ./script/install.sh
uninstall:
	sudo bash -x ./script/uninstall.sh
prep:
	sudo bash -x ./script/prep.sh
unprep:
	sudo bash -x ./script/unprep.sh
