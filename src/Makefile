SUBDIRS = sbin/hammer2 sbin/newfs_hammer2 sbin/mount_hammer2 sbin/fsck_hammer2

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
