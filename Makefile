BIN = btagent

PKG_CONFIG  ?= pkg-config
DBUS_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags dbus-1)
DBUS_LIBS   ?= $(shell $(PKG_CONFIG) --libs dbus-1)

CFLAGS += $(DBUS_CFLAGS)
LIBS   += $(DBUS_LIBS)

$(BIN): btagent.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

clean:
	@rm -f $(BIN) *.o
