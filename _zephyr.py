import os
import pwd
import time
import select

import cffi

ffi = cffi.FFI()

ffi.cdef("""
/* netinet/in.h */

struct in_addr { ...; };
struct sockaddr_in { ...; };

/* arpa/inet.h */

char * inet_ntoa(struct in_addr);
int inet_aton(char *, struct in_addr *);

/* zephyr/zephyr.h */

typedef enum {
    UNSAFE = 0, UNACKED = 1, ACKED = 2, HMACK = 3, HMCTL = 4, SERVACK = 5,
    SERVNAK = 6, CLIENTACK = 7, STAT = 8
} ZNotice_Kind_t;

#define ZAUTH_FAILED    ...
#define ZAUTH_YES       ...
#define ZAUTH_NO        ...

#define Z_MAXOTHERFIELDS  ...

struct _ZTimeval {
	int tv_sec;
	int tv_usec;
};

typedef struct _ZUnique_Id_t {
    struct	in_addr zuid_addr;
    struct	_ZTimeval	tv;
} ZUnique_Id_t;

typedef struct _ZNotice_t {
    ZNotice_Kind_t	z_kind;
    ZUnique_Id_t	z_uid;
    struct		_ZTimeval z_time;
    unsigned short      z_port;
    int			z_auth;
    int			z_checked_auth;
    char		*z_class;
    char		*z_class_inst;
    char		*z_opcode;
    char		*z_sender;
    char		*z_recipient;
    char		*z_default_format;
    int			z_num_other_fields;
    char		*z_other_fields[...];
    char                *z_message;
    int			z_message_len;
    ...;
} ZNotice_t;

typedef struct _ZSubscriptions_t {
    char	*zsub_recipient;
    char	*zsub_class;
    char	*zsub_classinst;
} ZSubscription_t;

typedef int Code_t;

typedef Code_t (*Z_AuthProc)(ZNotice_t*, char *, int, int *);

Code_t ZInitialize(void);
Code_t ZSetFD(int);
Code_t ZOpenPort(unsigned short *port);
int ZGetFD (void);
Code_t ZSubscribeTo(ZSubscription_t *sublist, int nitems,
		    unsigned int port);
Code_t ZUnsubscribeTo(ZSubscription_t *sublist, int nitems,
		      unsigned int port);
Code_t ZCancelSubscriptions(unsigned int port);
Code_t ZRetrieveSubscriptions(unsigned short, int*);
Code_t ZGetSubscriptions(ZSubscription_t *, int *);
int ZPending(void);
char *ZGetSender(void);
const char *ZGetRealm(void);

Code_t ZReceiveNotice(ZNotice_t *notice, struct sockaddr_in *from);
Code_t ZCheckAuthentication(ZNotice_t*, struct sockaddr_in*);

/* com_err.h */

const char *error_message(int);

""")

C = ffi.verify("""
#include <zephyr/zephyr.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <com_err.h>
""", libraries = ['zephyr', 'com_err'])

def __error(errno):
    if errno != 0:
        raise IOError(errno, ffi.string(C.error_message(errno)))

class ZUid(object):
    """
    A per-transaction unique ID for zephyrs
    """

    def __init__(self):
        self.address = ''
        self.time = 0

    def to_c(self):
        c_uid = ffi.new("ZUnique_Id_t*")
        C.inet_aton(self.address, ffi.addressof(c_uid.zuid_addr))
        c_uid.tv.tv_sec = int(self.time)
        c_uid.tv.tv_usec = int((self.time - int(self.time)) * 100000)
        return c_uid

    @classmethod
    def from_c(cls, c_uid):
        uid = cls()
        uid.address = ffi.string(C.inet_ntoa(c_uid.zuid_addr))
        uid.time    = c_uid.tv.tv_sec + (c_uid.tv.tv_usec / 100000.0)
        return uid

class ZephyrObjectDecorator(object):
    def __init__(self, cls):
        self.decorated = cls
        self.c_type     = ffi.typeof(cls.__ctype__)
        self.c_ptr_type = ffi.getctype(self.c_type, "*")

    def init(self, inst, c_object):
        inst.__dict__['__c_object'] = c_object or ffi.new(self.c_ptr_type)
        inst.__dict__['__c_strings'] = {}

    def get(self, inst, attr):
        return getattr(inst.__dict__['__c_object'], attr)

    def set(self, inst, attr, value):
        if isinstance(value, str):
            value = ffi.new("char[]", value)
            inst.__dict__['__c_strings'][attr] = value
        setattr(inst.__dict__['__c_object'], attr, value)

class ZephyrObjectType(type):
    def __init__(cls, name, bases, d):
        super(ZephyrObjectType, cls).__init__(name, bases, d)
        cls.__decorator__ = ZephyrObjectDecorator(cls)

class ZephyrObject(object):
    __metaclass__ = ZephyrObjectType
    __ctype__     = "void"

    def __init__(self, c_object=None):
        self.__decorator__.init(self, c_object)

    def __getattr__(self, attr):
        return self.__decorator__.get(self, attr)

    def __setattr__(self, attr, value):
        return self.__decorator__.set(self, attr, value)

class CZUid(ZephyrObject):
    __ctype__ = 'ZUnique_Id_t'

class CZNotice(ZephyrObject):
    __ctype__ = 'ZNotice_t'

class CZSubscription(ZephyrObject):
    __ctype__ = 'ZSubscription_t'

class ZNotice(object):
    """
    A zephyr message
    """

    def __init__(self, **options):
        self.kind = C.ACKED
        self.cls = 'message'
        self.instance = 'personal'

        self.uid = ZUid()
        self.time = 0
        self.port = 0
        self.auth = True
        self.recipient = None
        self.sender = None
        self.opcode = None
        self.format = "Class $class, Instance $instance:\nTo: @bold($recipient) at $time $date\nFrom: @bold{$1 <$sender>}\n\n$2"
        self.other_fields = []
        self.fields = []

        for k, v in options.iteritems():
            setattr(self, k, v)

    def getmessage(self):
        return '\0'.join(self.fields)

    def setmessage(self, newmsg):
        self.fields = newmsg.split('\0')

    message = property(getmessage, setmessage)

    def send(self):
        c_notice = self.to_c()

        original_message = self.message

        if self.auth:
            errno = C.ZSendNotice(c_notice.__c_object, C.ZAUTH)
        else:
            errno = C.ZSendNotice(c_notice.__c_object, C.ZNOAUTH)
        __error(errno)

        self.load_from_c(c_notice)

        self.message = original_message

        C.ZFreeNotice(c_notice.__c_object)

    def load_from_c(self, c_notice):
        self.kind = c_notice.z_kind
        self.uid = ZUid.from_c(c_notice.z_uid)
        self.time = c_notice.z_time.tv_sec + (c_notice.z_time.tv_usec / 100000.0)
        self.port = int(c_notice.z_port)
        self.auth = bool(c_notice.z_auth)

        self.cls = ffi.string(c_notice.z_class)
        self.instance = ffi.string(c_notice.z_class_inst)
        self.recipient = ffi.string(c_notice.z_recipient)
        self.sender = ffi.string(c_notice.z_sender)
        self.opcode = ffi.string(c_notice.z_opcode)
        self.format = ffi.string(c_notice.z_default_format)
        self.other_fields = list()
        for i in range(c_notice.z_num_other_fields):
            self.other_fields.append(ffi.string(c_notice.z_other_fields[i]))

        if c_notice.z_message == ffi.NULL:
            self.message = None
        else:
            self.message = ffi.buffer(c_notice.z_message, c_notice.z_message_len)[:]

    @classmethod
    def from_c(cls, c_notice):
        notice = cls()
        notice.load_from_c(c_notice)
        return notice

    def to_c(self):
        c_notice = CZNotice()

        c_notice.z_kind = self.kind
        c_notice.z_uid  = self.uid.to_c()
        if self.time != 0:
            c_notice.z_time.tv_sec = int(self.time)
            c_notice.z_time.tv_usec = int((self.time - c_notice.z_time.tv_sec) * 100000)
        if notice.port != 0:
            c_notice.z_port = self.port
        c_notice.z_auth = int(self.auth)

        c_notice.z_class = self.cls
        c_notice.z_class_inst = self.instance
        c_notice.z_recipient = self.recipient
        c_notice.z_sender = self.sender
        c_notice.z_opcode = self.opcode
        c_notice.z_default_format = self.format
        c_notice.z_num_other_fields = len(self.other_fields)
        for i, field in enumerate(self.other_fields):
            c_notice.z_other_fields[i] = field

        if isinstance(self.message, unicode):
            self.encoded_message = self.message.encode('utf-8')
        else:
            self.encoded_message = self.message

        c_notice.z_message = self.encoded_message
        c_notice.z_message_len = len(self.encoded_message)

def initialize():
    __error(C.ZInitialize())

def openPort():
    port = ffi.new('unsigned short *')
    port[0] = 0

    __error(C.ZOpenPort(port))

    return int(port[0])

def getFD():
    return C.ZGetFD()

def setFD(fd):
    __error(C.ZSetFD(fd))

def sub(cls, instance, recipient):
    newsub = CZSubscription()

    newsub.zsub_class     = cls
    newsub.zsub_classinst = instance
    newsub.zsub_recipient = recipient

    __error(C.ZSubscribeTo(newsub.__c_object, 1, 0))

def subAll(lst):
    memory = ffi.new('ZSubscription_t[]', len(lst))
    csubs  = memory.map(CZSubscription)

    for i, sub in enumerate(lst):
        csubs[i].zsub_class     = sub[0]
        csubs[i].zsub_classinst = sub[1]
        csubs[i].zsub_recipient = sub[2]

    __error(C.ZSubscribeTo(memory, len(lst), 0))

def unsub(cls, instance, recipient):
    delsub = CZSubscription()

    delsub.zsub_class     = cls
    delsub.zsub_classinst = instance
    delsub.zsub_recipient = recipient

    __error(C.ZUnsubscribeTo(delsub, 1, 0))

def cancelSubs():
    __error(C.ZCancelSubscriptions(0))

def receive(block=False):
    while C.ZPending() == 0:
        if not block:
            return None
        select.select([getFD()], [], [])

    c_notice = CZNotice()
    sender = ffi.new('struct sockaddr_in *')
    __error(C.ZReceiveNotice(c_notice.__c_object, sender))

    if C.ZCheckAuthentication(c_notice.__c_object, sender) == C.ZAUTH_YES:
        c_notice.z_auth = 1
    else:
        c_notice.z_auth = 0

    return ZNotice.from_c(c_notice)

def sender():
    return ffi.string(C.ZGetSender())

def realm():
    return ffi.string(C.ZGetRealm())

def getSubscriptions():
    c_num = ffi.new('int *')
    __error(C.ZRetrieveSubscriptions(0, c_num))

    csubs = ffi.new("ZSubscription_t[]", int(c_num[0]))
    __error(C.ZGetSubscriptions(csubs, c_num))

    subs = [(ffi.string(csubs[i].zsub_class),
             ffi.string(csubs[i].zsub_classinst),
             ffi.string(csubs[i].zsub_recipient))
            for i in xrange(int(c_num[0]))]
    return subs
