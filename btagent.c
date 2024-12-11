#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <dbus/dbus.h>

#ifndef BTAGT_PATH
#define BTAGT_PATH "/org/bluez/BTAgent"
#endif

#ifndef BTAGT_TYPE
#define BTAGT_TYPE "NoInputNoOutput"
#endif

const char *btagt_path = BTAGT_PATH;
const char *btagt_type = BTAGT_TYPE;

#define BTAGT_INTF "org.bluez.Agent1"

#define BTAGT_BLUEZ_NAME      "org.bluez"
#define BTAGT_BLUEZ_PATH      "/org/bluez"
#define BTAGT_BLUEZ_INTF_MGMT "org.bluez.AgentManager1"

#define BTAGT_MATCH \
    "type='"      "signal"            "'," \
    "sender='"    DBUS_SERVICE_DBUS   "'," \
    "path='"      DBUS_PATH_DBUS      "'," \
    "interface='" DBUS_INTERFACE_DBUS "'," \
    "member='"    "NameOwnerChanged"  "'," \
    "arg0='"      BTAGT_BLUEZ_NAME    "'"

enum btagt_meth {
    BTAGT_METH_REQUEST_PIN_CODE,
    BTAGT_METH_DISPLAY_PIN_CODE,
    BTAGT_METH_REQUEST_PASSKEY,
    BTAGT_METH_DISPLAY_PASSKEY,
    BTAGT_METH_REQUEST_CONFIRMATION,
    BTAGT_METH_REQUEST_AUTHORIZATION,
    BTAGT_METH_AUTHORIZE_SERVICE,
    BTAGT_METH_CANCEL,
    BTAGT_METH_RELEASE,
    BTAGT_METH_MAX_,
};

static const char *btagt_meth_table[] = {
    "RequestPinCode",
    "DisplayPinCode",
    "RequestPasskey",
    "DisplayPasskey",
    "RequestConfirmation",
    "RequestAuthorization",
    "AuthorizeService",
    "Cancel",
    "Release",
};

static struct {
    DBusConnection *d;
    volatile sig_atomic_t quit;
    int should_register;
} btagt;

static enum btagt_meth
btagt_parse_meth(const char *meth)
{
    for (enum btagt_meth m = 0; m < BTAGT_METH_MAX_; m++) {
        if (!strcmp(meth, btagt_meth_table[m]))
            return m;
    }
    return BTAGT_METH_MAX_;
}

static int
btagt_register(void)
{
    DBusError err;
    dbus_error_init(&err);

    DBusMessage *msg = dbus_message_new_method_call(
            BTAGT_BLUEZ_NAME,
            BTAGT_BLUEZ_PATH,
            BTAGT_BLUEZ_INTF_MGMT,
            "RegisterAgent");
    if (!msg) {
        fprintf(stderr, "Couldn't create D-Bus message\n");
        return -1;
    }
    dbus_message_append_args(msg,
            DBUS_TYPE_OBJECT_PATH, &btagt_path,
            DBUS_TYPE_STRING, &btagt_type,
            DBUS_TYPE_INVALID);

    dbus_connection_send_with_reply_and_block(btagt.d, msg, 1000, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Couldn't send message: %s\n", err.message);
        return -1;
    }
    dbus_message_unref(msg);

    msg = dbus_message_new_method_call(
            BTAGT_BLUEZ_NAME,
            BTAGT_BLUEZ_PATH,
            BTAGT_BLUEZ_INTF_MGMT,
            "RequestDefaultAgent");
    if (!msg) {
        fprintf(stderr, "Couldn't create D-Bus message\n");
        return -1;
    }
    dbus_message_append_args(msg,
                             DBUS_TYPE_OBJECT_PATH, &btagt_path,
                             DBUS_TYPE_INVALID);

    dbus_connection_send_with_reply_and_block(btagt.d, msg, 1000, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Couldn't send message: %s\n", err.message);
        return -1;
    }
    dbus_message_unref(msg);

    return 0;
}

static DBusHandlerResult
btagt_accept(DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    if (!dbus_connection_send(btagt.d, reply, NULL)) {
        fprintf(stderr, "Error when sending reply\n");
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
btagt_reject(DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_error(msg,
                                                "org.bluez.Error.Rejected",
                                                NULL);
    if (!reply)
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    if (!dbus_connection_send(btagt.d, reply, NULL)) {
        fprintf(stderr, "Error when sending reply\n");
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
btagt_request_confirmation(DBusMessage *msg)
{
    DBusError err;
    const char *device_path;
    unsigned long passkey;

    dbus_error_init(&err);

    if (!dbus_message_get_args(msg, &err,
                               DBUS_TYPE_OBJECT_PATH, &device_path,
                               DBUS_TYPE_UINT32, &passkey,
                               DBUS_TYPE_INVALID)) {
        fprintf(stderr, "btagent: RequestConfirmation with invalid params\n");
        dbus_error_free(&err);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    printf("btagent: RequestConfirmation for %s (%lu)\n",
           device_path,
           passkey);
    return btagt_accept(msg);
}

static DBusHandlerResult
btagt_request_authorization(DBusMessage *msg)
{
    DBusError err;
    const char *device_path;

    dbus_error_init(&err);

    if (!dbus_message_get_args(msg, &err,
                               DBUS_TYPE_OBJECT_PATH, &device_path,
                               DBUS_TYPE_INVALID)) {
        fprintf(stderr, "btagent: RequestAuthorization with invalid params\n");
        dbus_error_free(&err);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    printf("btagent: RequestAuthorization for %s\n", device_path);
    return btagt_accept(msg);
}

static DBusHandlerResult
btagt_authorize_service(DBusMessage *msg)
{
    DBusError err;
    const char *device_path;
    const char *uuid;

    dbus_error_init(&err);

    if (!dbus_message_get_args(msg, &err,
                               DBUS_TYPE_OBJECT_PATH, &device_path,
                               DBUS_TYPE_STRING, &uuid,
                               DBUS_TYPE_INVALID)) {
        fprintf(stderr, "btagent: AuthorizeService with invalid params\n");
        dbus_error_free(&err);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    printf("btagent: AuthorizeService for %s (%s)\n", device_path, uuid);
    return btagt_accept(msg);
}

static DBusHandlerResult
btagt_agent_handler(DBusConnection *d, DBusMessage *msg, void *user_data)
{
    const char *path = dbus_message_get_path(msg);
    const char *intf = dbus_message_get_interface(msg);
    const char *memb = dbus_message_get_member(msg);

    if (strcmp(path, BTAGT_PATH) || strcmp(intf, BTAGT_INTF))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    enum btagt_meth meth = btagt_parse_meth(memb);

    switch (meth) {
    case BTAGT_METH_REQUEST_CONFIRMATION:
        return btagt_request_confirmation(msg);

    // When JustWorksRepairing = confirm and repairing without removing device
    // and agent type is NoInputNoOuput
    case BTAGT_METH_REQUEST_AUTHORIZATION:
        return btagt_request_authorization(msg);

    case BTAGT_METH_AUTHORIZE_SERVICE:
        return btagt_authorize_service(msg);

    case BTAGT_METH_CANCEL:
        return DBUS_HANDLER_RESULT_HANDLED;

    // When bluez gracefully quits, it unregisters us
    case BTAGT_METH_RELEASE:
        btagt.quit = 1;
        return DBUS_HANDLER_RESULT_HANDLED;

    default:
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
}

static DBusHandlerResult
btagt_filter_handler(DBusConnection *d, DBusMessage *msg, void *user_data)
{
    DBusError err;
    const char *who, *old, *new;

    dbus_error_init(&err);
    int type           = dbus_message_get_type(msg);
    const char *sender = dbus_message_get_sender(msg);
    const char *path   = dbus_message_get_path(msg);
    const char *intf   = dbus_message_get_interface(msg);
    const char *memb   = dbus_message_get_member(msg);

    if (type != DBUS_MESSAGE_TYPE_SIGNAL    ||
        strcmp(sender, DBUS_SERVICE_DBUS  ) ||
        strcmp(path,   DBUS_PATH_DBUS     ) ||
        strcmp(intf,   DBUS_INTERFACE_DBUS) ||
        strcmp(memb,   "NameOwnerChanged" ))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (!dbus_message_get_args(msg, &err,
                               DBUS_TYPE_STRING, &who,
                               DBUS_TYPE_STRING, &old,
                               DBUS_TYPE_STRING, &new,
                               DBUS_TYPE_INVALID)) {
        fprintf(stderr, "btagent: NameOwnerChanged with invalid params\n");
        dbus_error_free(&err);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (strcmp(who, BTAGT_BLUEZ_NAME))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    // bluez appeared
    if (!strcmp(old, "") && strcmp(new, "")) {
        btagt.should_register = 1;
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

static int
btagt_name_has_owner(const char *name)
{
    DBusError err;
    DBusMessage *msg, *reply;
    dbus_bool_t has_owner;

    dbus_error_init(&err);

    msg = dbus_message_new_method_call(
            DBUS_SERVICE_DBUS,
            DBUS_PATH_DBUS,
            DBUS_INTERFACE_DBUS,
            "NameHasOwner");
    if (!msg) {
        fprintf(stderr, "Couldn't create D-Bus message\n");
        return -1;
    }
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);

    reply = dbus_connection_send_with_reply_and_block(btagt.d, msg, 1000, &err);
    if (!reply) {
        fprintf(stderr, "Couldn't send message: %s\n", err.message);
        return -1;
    }
    dbus_message_unref(msg);

    if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_METHOD_RETURN)
        return -1;

    if (!dbus_message_get_args(reply, &err,
                               DBUS_TYPE_BOOLEAN, &has_owner,
                               DBUS_TYPE_INVALID)) {
        fprintf(stderr, "btagent: NameHasOwner reply with invalid params\n");
        dbus_error_free(&err);
        return -1;
    }
    dbus_message_unref(reply);

    return has_owner ? 1 : 0;
}

static void
btagt_sa_handler(int sig)
{
    btagt.quit = 1;
}

static void
btagt_set_signal(void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = btagt_sa_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
}

int
main(void)
{
    btagt_set_signal();

    DBusError err;
    dbus_error_init(&err);

    DBusConnection *d = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!d) {
        fprintf(stderr, "Failed to connect to D-Bus: %s\n", err.message);
        dbus_error_free(&err);
        return -1;
    }
    btagt.d = d;

    DBusObjectPathVTable vtable = {
        .message_function = btagt_agent_handler,
    };

    if (!dbus_connection_register_object_path(btagt.d, BTAGT_PATH, &vtable, NULL)) {
        fprintf(stderr, "Failed to register path %s\n", BTAGT_PATH);
        return -1;
    }

    if (!dbus_connection_add_filter(btagt.d, btagt_filter_handler, NULL, NULL)) {
        fprintf(stderr, "Failed to add filter\n");
        return -1;
    }

    dbus_bus_add_match(btagt.d, BTAGT_MATCH, &err);
    if(dbus_error_is_set(&err)) {
        fprintf(stderr, "Failed to add match\n");
        return -1;
    }

    int ret = btagt_name_has_owner(BTAGT_BLUEZ_NAME);
    switch (ret) {
    case 1:
        btagt.should_register = 1;
        break;

    case 0:
        printf("btagent: Waiting for bluez to appear\n");
        break;

    default:
        return ret;
    }

    while (!btagt.quit) {
        if (btagt.should_register && !btagt_register()) {
            btagt.should_register = 0;
            printf("btagent: Agent registered with bluez!\n");
        }

        dbus_connection_read_write_dispatch(d, 1000);
    }

    return 0;
}
