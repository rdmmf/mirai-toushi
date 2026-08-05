# Extract additional data (e.g., C2 in resolv_cnc_addr(), DoS function) from Mirai main.c/attack.c
# @author Shun Morishita
# @category Analysis
# @runtime Jython

import collections
import json
import re

try:
    import __main__ as ghidra_app
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.program.database.code import DataDB
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.block import IsolatedEntrySubModel
    from ghidra.util.task import ConsoleTaskMonitor
    HAS_GHIDRA = True
except ImportError:
    # allows running the pure-python helpers under CPython for selfTest()
    HAS_GHIDRA = False


KEY_SCRIPT_NAME = "script_name"
KEY_GHIDRA_CURRENT_PROGRAM = "ghidra_current_program"
KEY_NAME = "name"
KEY_PATH = "path"
KEY_SHA256 = "sha256"
KEY_LANGUAGE_ID = "language_id"
KEY_IMAGE_BASE = "image_base"
KEY_MIN_ADDR = "min_addr"
KEY_MAX_ADDR = "max_addr"
KEY_MAIN_FUNC = "main_func"
KEY_ENTRYPOINT = "entrypoint"
KEY_RESOLVE_CNC_ADDR_FUNC = "resolve_cnc_addr_func"
KEY_CNC = "cnc"
KEY_ATTACK_INIT_FUNC = "attack_init_func"
KEY_ATTACKS_COUNT = "attacks_count"
KEY_ATTACKS = "attacks"
KEY_VECTOR = "vector"
KEY_HOW = "how"
KEY_CNC_IMMEDIATES = "cnc_immediates"
KEY_IP = "ip"
KEY_PORT = "port"
KEY_ROLE = "role"
KEY_BEST = "best"
KEY_FUNC = "func"
KEY_ADDR = "addr"
KEY_RAW_CONST = "raw_const"
KEY_BYTE_ORDER = "byte_order"
KEY_SOCKADDR_ADDR = "sockaddr_addr"
KEY_IN_MAIN = "in_main"
KEY_HAS_CONNECT = "has_connect"

ROLE_CNC = "cnc"
ROLE_RESOLVER = "resolver"
ROLE_BIND = "bind"

ORDER_WRAPPER = "wrapper"
ORDER_MEMORY = "memory"

MNE_CALL = "CALL"
MNE_CALLIND = "CALLIND"
MNE_COPY = "COPY"
MNE_STORE = "STORE"
MNE_LOAD = "LOAD"
MNE_CAST = "CAST"
MNE_INT_ADD = "INT_ADD"
MNE_INT_SUB = "INT_SUB"
MNE_INT_OR = "INT_OR"
MNE_INT_LEFT = "INT_LEFT"
MNE_INT_ZEXT = "INT_ZEXT"
MNE_INT_SEXT = "INT_SEXT"
MNE_SUBPIECE = "SUBPIECE"
MNE_PTRSUB = "PTRSUB"
MNE_PTRADD = "PTRADD"
MNE_MULTIEQUAL = "MULTIEQUAL"
MNE_INDIRECT = "INDIRECT"

AF_INET = 2
# sin_port lives at +2, sin_addr at +4 in every sockaddr_in we care about
OFF_PORT = 2
OFF_ADDR = 4
# Mirai binds this port to enforce a single instance
PORT_SINGLE_INSTANCE = 48101
PORT_DNS = 53
PUBLIC_RESOLVERS = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "4.2.2.1", "4.2.2.2")
GROUP_ABS = "abs"
# cap the work when main cannot be identified
MAX_FALLBACK_FUNCS = 60
MIN_FALLBACK_BODY = 200

ARCH_ARM_BE = "ARM:BE:32:v8"
ARCH_ARM_LE = "ARM:LE:32:v8"
ARCH_M68K = "68000:BE:32:Coldfire"
ARCH_MIPS_BE = "MIPS:BE:32:default"
ARCH_MIPS_LE = "MIPS:LE:32:default"
ARCH_PPC = "PowerPC:BE:32:default"
ARCH_SH4 = "SuperH4:LE:32:default"
ARCH_SPC = "sparc:BE:32:default"
ARCH_X86 = "x86:LE:32:default"
ARCH_X86_64 = "x86:LE:64:default"

SCRIPT_NAME = "parse_main.py"
LANGS = [
    ARCH_ARM_BE, ARCH_ARM_LE, ARCH_M68K, ARCH_MIPS_BE,
    ARCH_MIPS_LE, ARCH_PPC, ARCH_SH4, ARCH_SPC,
    ARCH_X86, ARCH_X86_64
    ]


def defUndefinedFuncs(listing, monitor):
    # ref. https://github.com/EliasKotlyar/Med9GhidraScripts/blob/main/general/DefineUndefinedFunctions.py
    addr_set = AddressSet()
    instructs = listing.getInstructions(currentProgram.getMemory(), True)
    while instructs.hasNext() and not monitor.isCancelled():
        instruct = instructs.next()
        addr_set.addRange(instruct.getMinAddress(), instruct.getMaxAddress())
    funcs = listing.getFunctions(True)
    while funcs.hasNext() and not monitor.isCancelled():
        func = funcs.next()
        addr_set.delete(func.getBody())
    if addr_set.getNumAddressRanges() == 0:
        return None
    # go through address set and find actual start of flow into dead code
    submodel = IsolatedEntrySubModel(currentProgram)
    subIter = submodel.getCodeBlocksContaining(addr_set, monitor)
    codeStarts = AddressSet()
    # sometimes IsolatedEntrySubModel() doesnt work correctly, we set the maximum value to 1000
    i = 0
    while subIter.hasNext():
        if i >= 1000:
            return None
        block = subIter.next()
        deadStart = block.getFirstStartAddress()
        codeStarts.add(deadStart)
        i += 1
    for startAdr in codeStarts:
        phyAdr = startAdr.getMinAddress()
        createFunction(phyAdr, None)
    return None


def countCloseSeq(text):
    """Count `... (0); ... (1); ... (2);` sequences, one line at a time.

    Same answer as re.findall(r".+?\\(0\\);.+?\\(1\\);.+?\\(2\\);", text) - the
    tokens must appear in order on a single line ("." never matched a newline),
    with at least one character before and between them - but linear instead of
    quadratic. The regex backtracks catastrophically on the large functions of
    a statically linked build: on one 99 KB decompiled libc function it spent
    426 s to return zero matches, which is what made those samples time out.
    """
    total = 0
    for line in text.split("\n"):
        pos = 0
        while True:
            # +1 / +5: the leading and separating .+? need one character each
            a = line.find("(0);", pos + 1)
            if a < 0:
                break
            b = line.find("(1);", a + 5)
            if b < 0:
                break
            c = line.find("(2);", b + 5)
            if c < 0:
                break
            total += 1
            pos = c + 4
    return total


def getMainFunc(func_mgr, ifc, monitor):
    main_func = main_ccode = None
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        addr_num = func.getBody().getNumAddresses()
        if addr_num < 1000:
            continue
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        if countCloseSeq(ccode.toString()) != 1:
            continue
        # this regex has the same backtracking shape as the one above, but it
        # only runs on the few functions that pass the close(0/1/2) filter
        c2conn_strs = re.findall(
                r"(do|while\( true \)) \{.+?if \(.+? != .+?(0xffffffff|\-1)\) \{.+?\}.+?if \(.+? == .+?(0xffffffff|\-1)\)",
                ccode.toString()
                )
        if 1 <= len(c2conn_strs) <= 2:
            main_func = func
            main_ccode = ccode
            break
    return main_func, main_ccode


def getResolveCncAddrFunc(listing, func_mgr, ifc, monitor, main_func, main_ccode):
    resolve_cnc_addr_func = cnc = None
    language_id = currentProgram.getLanguageID().toString()
    func_names = [func.getName() for func in func_mgr.getFunctions(True)]
    lines = re.findall(r"[0-9a-zA-Z|_]+? = [0-9a-zA-Z|_]+?;", main_ccode.toString())
    for line in lines:
        match = re.search(r"[0-9a-zA-Z|_]+? = ([0-9a-zA-Z|_]+?);", line)
        if not match:
            continue
        func_name = match.group(1)
        if func_name not in func_names:
            continue
        func = getGlobalFunctions(func_name)[0]
        if language_id not in (ARCH_MIPS_BE, ARCH_MIPS_LE):
            entry_point = func.getEntryPoint()
            refs = getReferencesTo(entry_point)
            cand_caller_funcs = []
            for ref in refs:
                cand_caller_func = None
                # in some cases (sh4), getFunctionContaining cannot identify function correctly
                if language_id == ARCH_SH4:
                    cand_caller_func = getFunctionBefore(ref.getFromAddress())
                else:
                    cand_caller_func = getFunctionContaining(ref.getFromAddress())
                cand_caller_funcs.append(cand_caller_func)
            cand_caller_funcs = [cc_func for cc_func in cand_caller_funcs if cc_func is not None]
            # cand_caller_funcs contain main_func (+ anti_gdb_entry)
            # in some cases (mips), ghidra doesnt handle xref correctly
            if main_func not in cand_caller_funcs:
                continue
        cnc = getCnc(listing, ifc, monitor, func)
        if cnc:
            resolve_cnc_addr_func = func
            break
    return resolve_cnc_addr_func, cnc


def getCnc(listing, ifc, monitor, resolve_cnc_addr_func):
    cnc = ""
    instructs = list(listing.getInstructions(resolve_cnc_addr_func.getBody(), True))
    for instruct in instructs:
        refs = getReferencesFrom(instruct.getAddress())
        if len(refs) == 0:
            continue
        for ref in refs:
            addr = ref.getToAddress()
            data = getDataAt(addr)
            if not isinstance(data, DataDB):
                continue
            cnc = ""
            try:
                for count in range(1024):
                    byte = getUByte(addr.add(count))
                    # null
                    if byte == 0:
                        break
                    # convert ascii printable characters
                    elif 32 <= byte <= 126:
                        cnc += chr(byte)
                    else:
                        cnc += "\\x{:02x}".format(byte)
                # check domain / ip address
                if (re.match(r"^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$", cnc) or
                        re.match(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", cnc)):
                    break
                else:
                    cnc = ""
            except:
                pass
        if cnc:
            break
    if cnc:
        return cnc
    # parse 4 bytes to ip address
    ccode = getDecompileCCode(resolve_cnc_addr_func, ifc, monitor)
    if not ccode:
        return ""
    # ; srv_addr._4_4_ = 0xc229a6bc;
    # ; srv_addr._4_4_ = htonl(0xb9f698ad);
    match = re.search(r"[^{;(,]+? = ([^{;(,]*)\(?(0x[0-9a-fA-F]{7,8})\)?;", ccode.toString())
    if not match:
        return ""
    cnc_int = int(match.group(2), 16)
    byte_list = []
    byte_list.append(str((cnc_int >> 24) & 0xFF))
    byte_list.append(str((cnc_int >> 16) & 0xFF))
    byte_list.append(str((cnc_int >> 8) & 0xFF))
    byte_list.append(str((cnc_int >> 0) & 0xFF))
    language_id = currentProgram.getLanguageID().toString()
    endian = language_id.split(":")[1]
    # if this instruction uses htonl(), dont reverse bytes
    if match.group(1):
        pass
    elif endian == "LE" or language_id == ARCH_ARM_BE:
        byte_list.reverse()
    cnc = ".".join(byte_list)
    return cnc


# --------------------------------------------------------------------------
# C2 hardcoded as a numeric immediate in the sockaddr_in setup
#
# Many Mirai forks never store the C2 as a string, and never keep it in the
# table either: they write the address and port straight into a sockaddr_in as
# 32/16 bit literals, e.g.
#
#   _DAT_00512640 = 2;            // sin_family = AF_INET
#   _DAT_00512642 = 0x1700;       // sin_port   = 23
#   _DAT_00512644 = 0x5f3447a7;   // sin_addr   = 167.71.52.95
#
#   *DAT_000107ac = 2;
#   *(sa + 2) = htons(0x46d1);    // 18129
#   *(sa + 4) = htonl(0xb5d663b4);// 181.214.99.180
#
# getCnc() above only reaches this when the constant sits in resolve_cnc_addr()
# in the exact shape its regex expects. The scan below anchors on the socket
# setup itself - a write of AF_INET (2), then constant writes 2 and 4 bytes
# further into the same struct - so it also finds the C2 when it is built in
# main() or in any of its callees, on any of the supported architectures.
# --------------------------------------------------------------------------

# pure helpers (no Ghidra API, covered by selfTest())

def intToBytes(value, size):
    """big-endian byte list of a `size`-byte word"""
    out = []
    for i in range(size):
        out.append((value >> (8 * (size - 1 - i))) & 0xFF)
    return out


def toNetworkBytes(value, size, byte_order, language_id):
    """Return the bytes as they hit the wire.

    A value that went through htons()/htonl() is a host-order number, so its
    big-endian rendering is already the network order. A value written straight
    into memory is read back in program byte order, so on little endian the
    memory image is the reverse of the big-endian rendering. ARM:BE:32:v8 is
    treated as LE here, matching getCnc().
    """
    byte_list = intToBytes(value, size)
    if byte_order == ORDER_WRAPPER:
        return byte_list
    endian = language_id.split(":")[1] if ":" in language_id else "BE"
    if endian == "LE" or language_id == ARCH_ARM_BE:
        byte_list.reverse()
    return byte_list


def bytesToIp(byte_list):
    return ".".join([str(b) for b in byte_list])


def isGlobalUnicast(byte_list):
    """reject anything that cannot be a routable C2"""
    if len(byte_list) != 4:
        return False
    a, b = byte_list[0], byte_list[1]
    if a == 0 or a == 127 or a >= 224:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if byte_list == [255, 255, 255, 255]:
        return False
    # a C2 with two zero octets is a constant that merely looks like an IP
    # (0x9 -> 9.0.0.0), and no reachable host has a zero last octet
    if byte_list[3] == 0:
        return False
    if len([x for x in byte_list if x == 0]) >= 2:
        return False
    return True


def looksLikeAddress(value, image_range):
    """a constant that lands inside the program image is a pointer, not an IP"""
    if not image_range:
        return False
    low, high = image_range
    return low <= value <= high


def classifyRole(ip, port):
    """Mirai opens 3 kinds of socket with a literal address"""
    if ip in PUBLIC_RESOLVERS and port == PORT_DNS:
        return ROLE_RESOLVER
    if port == PORT_SINGLE_INSTANCE:
        return ROLE_BIND
    return ROLE_CNC


def rankKey(cand):
    """total order over candidates: a C2 in main next to a connect() wins"""
    return (
        0 if cand[KEY_ROLE] == ROLE_CNC else 1,
        0 if cand[KEY_IN_MAIN] else 1,
        0 if cand[KEY_HAS_CONNECT] else 1,
        0 if cand[KEY_PORT] is not None else 1,
        cand[KEY_IP],
        )


def rankCandidates(candidates):
    """dedupe on (ip, port), sort, flag the winner"""
    best_by_key = collections.OrderedDict()
    for cand in candidates:
        key = (cand[KEY_IP], cand[KEY_PORT])
        if key not in best_by_key or rankKey(cand) < rankKey(best_by_key[key]):
            best_by_key[key] = cand
    ranked = list(best_by_key.values())
    ranked.sort(key=rankKey)
    for cand in ranked:
        cand[KEY_BEST] = False
    for cand in ranked:
        # a bare address with neither a port nor a connect call next to it is
        # not enough to name something the C2
        if cand[KEY_ROLE] != ROLE_CNC:
            continue
        if cand[KEY_PORT] is None and not cand[KEY_HAS_CONNECT]:
            continue
        cand[KEY_BEST] = True
        break
    return ranked


def makeCandidate(ip, port, role, func_name, addr_str, raw_const,
                  byte_order, sockaddr_addr, in_main=False, has_connect=False):
    cand = collections.OrderedDict()
    cand[KEY_IP] = ip
    cand[KEY_PORT] = port
    cand[KEY_ROLE] = role
    cand[KEY_BEST] = False
    cand[KEY_FUNC] = func_name
    cand[KEY_ADDR] = addr_str
    cand[KEY_RAW_CONST] = raw_const
    cand[KEY_BYTE_ORDER] = byte_order
    cand[KEY_SOCKADDR_ADDR] = sockaddr_addr
    cand[KEY_IN_MAIN] = in_main
    cand[KEY_HAS_CONNECT] = has_connect
    return cand


# Ghidra side

def getHighFunc(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    return res.getHighFunction()


def readPointer(addr, bits):
    try:
        if bits == 64:
            return getLong(addr) & 0xFFFFFFFFFFFFFFFF
        return getInt(addr) & 0xFFFFFFFF
    except:
        return None


def getMainFuncByLibcStart(func_mgr, ifc, monitor):
    """__libc_start_main(main, argc, argv, ...) - main is the first argument.

    Covers the forks whose main does not match getMainFunc()'s shape test: the
    entry thunk passes a pointer (ARM/x86 pass a DAT_ pointer, MIPS an indirect
    PTR_FUN_ call), and that pointer's *value* is main.
    """
    language_id = currentProgram.getLanguageID().toString()
    bits = int(language_id.split(":")[2])
    entry_points = []
    for addr in currentProgram.getSymbolTable().getExternalEntryPointIterator():
        entry_points.append(addr)
    for entry_addr in entry_points:
        func = getFunctionContaining(entry_addr)
        if not func:
            continue
        for depth_func in _entryChain(func, ifc, monitor):
            high_func = getHighFunc(depth_func, ifc, monitor)
            if not high_func:
                continue
            for pcode in high_func.getPcodeOps():
                if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
                    continue
                args = pcode.getInputs()[1:]
                if not args:
                    continue
                cand = _mainFromArg(args[0], bits, func_mgr)
                if cand:
                    return cand
    return None


def _entryChain(func, ifc, monitor):
    """entry itself plus the single function it tails into (x86/ARM stubs)"""
    chain = [func]
    ccode = getDecompileCCode(func, ifc, monitor)
    if not ccode:
        return chain
    for match in re.finditer(r"(FUN_[0-9a-fA-F]+)\(", ccode.toString()):
        callees = getGlobalFunctions(match.group(1))
        if callees and callees[0] not in chain:
            chain.append(callees[0])
    return chain[:3]


def _mainFromArg(varnode, bits, func_mgr):
    """turn a __libc_start_main first argument into a Function"""
    cands = []
    const = resolveConst(varnode, bits, depth=0)
    if const is not None:
        cands.append(const[0])
    addr_val = _varnodeAddress(varnode)
    if addr_val is not None:
        cands.append(addr_val)
        ptr = readPointer(toAddr(addr_val), bits)
        if ptr:
            cands.append(ptr)
    for cand in cands:
        if not cand:
            continue
        try:
            addr = toAddr(cand)
        except:
            continue
        if addr is None:
            continue
        func = getFunctionAt(addr)
        if func:
            return func
        # main may still be undefined code (MIPS/SH), create it
        if getInstructionAt(addr):
            func = createFunction(addr, None)
            if func:
                return func
    return None


def _varnodeAddress(varnode):
    try:
        addr = varnode.getAddress()
    except:
        return None
    if addr is None:
        return None
    try:
        if addr.getAddressSpace().isMemorySpace() or varnode.isConstant():
            return addr.getOffset()
    except:
        return None
    return None


def resolveConst(varnode, bits, depth=0, wrapper=False):
    """Evaluate a varnode to (value, wrapper_flag) when it is compile-time known.

    One evaluator covers both roles a varnode plays here - the value being
    stored, and the pointer expression saying where it goes - because a
    pointer's value *is* the address. Handles literal pools (a LOAD from, or a
    plain read of, a fixed address: how ARM/MIPS materialise a 32-bit
    constant), htons()/htonl() wrappers, and the lui/ori split immediate when
    the decompiler leaves it unfolded.
    """
    if varnode is None or depth > 12:
        return None
    if varnode.isConstant():
        return (varnode.getOffset(), wrapper)
    op = varnode.getDef()
    if op is None:
        # a global variable read: its value is the memory content
        addr_val = _varnodeAddress(varnode)
        if addr_val is None or varnode.isRegister():
            return None
        value = _readWord(addr_val, varnode.getSize())
        if value is None:
            return None
        return (value, wrapper)
    mnemonic = op.getMnemonic()
    inputs = op.getInputs()
    if mnemonic in (MNE_COPY, MNE_CAST, MNE_INT_ZEXT, MNE_INT_SEXT, MNE_SUBPIECE, MNE_INDIRECT):
        return resolveConst(inputs[0], bits, depth + 1, wrapper)
    if mnemonic == MNE_MULTIEQUAL:
        for inp in inputs:
            res = resolveConst(inp, bits, depth + 1, wrapper)
            if res is not None:
                return res
        return None
    if mnemonic == MNE_LOAD:
        # inputs[0] is the address space id, inputs[1] the pointer expression
        ptr = resolveConst(inputs[1], bits, depth + 1, wrapper)
        if ptr is None:
            return None
        value = _readWord(ptr[0], varnode.getSize())
        if value is None:
            return None
        return (value, ptr[1])
    if mnemonic in (MNE_CALL, MNE_CALLIND):
        # htons()/htonl() wrapper. Ghidra guesses the parameter list, so a
        # one-argument wrapper can show up with extra junk arguments; take the
        # first argument that is compile-time known.
        for arg in inputs[1:]:
            res = resolveConst(arg, bits, depth + 1, True)
            if res is not None:
                return res
        return None
    if mnemonic in (MNE_INT_OR, MNE_INT_ADD, MNE_INT_SUB, MNE_INT_LEFT, MNE_PTRSUB, MNE_PTRADD):
        left = resolveConst(inputs[0], bits, depth + 1, wrapper)
        right = resolveConst(inputs[1], bits, depth + 1, wrapper) if len(inputs) > 1 else None
        if left is None or right is None:
            return None
        if mnemonic == MNE_INT_OR:
            value = left[0] | right[0]
        elif mnemonic == MNE_INT_SUB:
            value = left[0] - right[0]
        elif mnemonic == MNE_INT_LEFT:
            value = (left[0] << right[0]) & 0xFFFFFFFF
        elif mnemonic == MNE_PTRADD and len(inputs) > 2 and inputs[2].isConstant():
            value = left[0] + right[0] * inputs[2].getOffset()
        else:
            value = left[0] + right[0]
        return (value, left[1] or right[1])
    return None


def _readWord(addr_val, size):
    try:
        addr = toAddr(addr_val)
        if addr is None:
            return None
        if size >= 8:
            return getLong(addr) & 0xFFFFFFFFFFFFFFFF
        if size >= 4:
            return getInt(addr) & 0xFFFFFFFF
        if size == 2:
            return getShort(addr) & 0xFFFF
        return getByte(addr) & 0xFF
    except:
        return None


def storeTarget(varnode, bits):
    """Where a store lands, as (group, offset).

    Absolute addresses share the single "abs" group, so a global sockaddr is
    matched on real addresses. When the base cannot be resolved - MIPS reaches
    its globals through $gp, and stack structs through the frame pointer - fall
    back to a symbolic group keyed on the base varnode, with the constant part
    peeled off as the offset. Relative offsets are all the sockaddr match needs.
    """
    absolute = resolveConst(varnode, bits)
    if absolute is not None:
        return (GROUP_ABS, absolute[0])
    node = varnode
    offset = 0
    for _ in range(12):
        op = node.getDef()
        if op is None:
            break
        mnemonic = op.getMnemonic()
        inputs = op.getInputs()
        if mnemonic in (MNE_COPY, MNE_CAST, MNE_INT_ZEXT, MNE_INT_SEXT, MNE_INDIRECT):
            node = inputs[0]
            continue
        if mnemonic in (MNE_INT_ADD, MNE_PTRSUB) and len(inputs) > 1 and inputs[1].isConstant():
            offset += inputs[1].getOffset()
            node = inputs[0]
            continue
        if mnemonic == MNE_PTRADD and len(inputs) > 2 and inputs[1].isConstant() and inputs[2].isConstant():
            offset += inputs[1].getOffset() * inputs[2].getOffset()
            node = inputs[0]
            continue
        if mnemonic == MNE_INT_SUB and len(inputs) > 1 and inputs[1].isConstant():
            offset -= inputs[1].getOffset()
            node = inputs[0]
            continue
        break
    return (_varnodeKey(node), offset)


def _varnodeKey(varnode):
    """stable identity for one SSA value, so writes through it group together"""
    op = varnode.getDef()
    seq = "-"
    if op is not None:
        try:
            seq = op.getSeqnum().toString()
        except:
            seq = str(op.getSeqnum())
    return varnode.toString() + "@" + seq


def collectWrites(high_func, bits):
    """Constant writes, grouped by target: {(group, offset): [(value, size, order, op_addr)]}"""
    writes = {}
    for pcode in high_func.getPcodeOps():
        mnemonic = pcode.getMnemonic()
        target = None
        value_vn = None
        size = None
        if mnemonic == MNE_STORE:
            inputs = pcode.getInputs()
            if len(inputs) < 3:
                continue
            target = storeTarget(inputs[1], bits)
            value_vn = inputs[2]
            size = inputs[2].getSize()
        elif mnemonic == MNE_COPY:
            out = pcode.getOutput()
            if out is None:
                continue
            addr_val = _globalOutputAddress(out)
            if addr_val is None:
                continue
            target = (GROUP_ABS, addr_val)
            value_vn = pcode.getInputs()[0]
            size = out.getSize()
        if target is None or value_vn is None:
            continue
        const = resolveConst(value_vn, bits)
        if const is None:
            continue
        op_addr = pcode.getSeqnum().getTarget()
        writes.setdefault(target, []).append(
                (const[0], size, ORDER_WRAPPER if const[1] else ORDER_MEMORY, op_addr))
    return writes


def _globalOutputAddress(varnode):
    if varnode.isRegister() or varnode.isConstant() or varnode.isUnique():
        return None
    try:
        addr = varnode.getAddress()
        if addr is None or not addr.getAddressSpace().isMemorySpace():
            return None
        return addr.getOffset()
    except:
        return None


def hasConnectShape(high_func):
    """crude: does this function call something with a (fd, ptr, 0x10) argument list"""
    for pcode in high_func.getPcodeOps():
        if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
            continue
        args = pcode.getInputs()[1:]
        if len(args) < 3:
            continue
        last = args[2]
        if last.isConstant() and last.getOffset() == 0x10:
            return True
    return False


def scanFunc(func, high_func, language_id, bits, in_main, image_range=None):
    """find sockaddr_in setups whose address (and ideally port) are literals"""
    candidates = []
    writes = collectWrites(high_func, bits)
    connect_shape = hasConnectShape(high_func)
    for (group, offset), entries in writes.items():
        if not [e for e in entries if e[0] == AF_INET and e[1] <= 4]:
            continue
        addr_entry = _pickWrite(writes, (group, offset + OFF_ADDR), 4)
        if addr_entry is None:
            continue
        if looksLikeAddress(addr_entry[0], image_range):
            continue
        ip_bytes = toNetworkBytes(addr_entry[0], 4, addr_entry[2], language_id)
        if not isGlobalUnicast(ip_bytes):
            continue
        ip = bytesToIp(ip_bytes)
        port = _portFromWrites(writes, group, offset, language_id)
        role = classifyRole(ip, port)
        if group == GROUP_ABS:
            sockaddr = hex(offset).rstrip("L")
        else:
            sockaddr = group
        candidates.append(makeCandidate(
            ip, port, role, func.getName(),
            addr_entry[3].toString() if addr_entry[3] else None,
            hex(addr_entry[0]).rstrip("L"),
            addr_entry[2],
            sockaddr,
            in_main,
            connect_shape))
    return candidates


def _portFromWrites(writes, group, offset, language_id):
    """sin_port, written either as one 16-bit word or as two single bytes"""
    entry = _pickWrite(writes, (group, offset + OFF_PORT), 2)
    if entry is not None and entry[1] == 2:
        port_bytes = toNetworkBytes(entry[0] & 0xFFFF, 2, entry[2], language_id)
        port = (port_bytes[0] << 8) | port_bytes[1]
        return port if 1 <= port <= 65535 else None
    high = _pickWrite(writes, (group, offset + OFF_PORT), 1)
    low = _pickWrite(writes, (group, offset + OFF_PORT + 1), 1)
    if high is None or low is None or high[1] != 1 or low[1] != 1:
        return None
    # single bytes are already in memory (= network) order
    port = ((high[0] & 0xFF) << 8) | (low[0] & 0xFF)
    return port if 1 <= port <= 65535 else None


def _pickWrite(writes, key, want_size):
    """the write at `key`, preferring the expected size; None if absent"""
    entries = writes.get(key)
    if not entries:
        return None
    sized = [e for e in entries if e[1] == want_size]
    if sized:
        return sized[-1]
    return entries[-1]


def targetFuncs(main_func, func_mgr, monitor):
    """main plus its direct callees; fall back to the biggest functions"""
    funcs = []
    if main_func:
        funcs.append((main_func, True))
        for callee in main_func.getCalledFunctions(monitor):
            if callee != main_func:
                funcs.append((callee, False))
        return funcs
    cands = []
    for func in func_mgr.getFunctions(True):
        size = func.getBody().getNumAddresses()
        if size >= MIN_FALLBACK_BODY:
            cands.append((size, func))
    cands.sort(key=lambda pair: -pair[0])
    for _, func in cands[:MAX_FALLBACK_FUNCS]:
        funcs.append((func, False))
    return funcs


def getCncImmediates(func_mgr, ifc, monitor, main_func, language_id):
    bits = int(language_id.split(":")[2])
    image_range = (currentProgram.getMinAddress().getOffset(),
                   currentProgram.getMaxAddress().getOffset())
    candidates = []
    for func, in_main in targetFuncs(main_func, func_mgr, monitor):
        high_func = getHighFunc(func, ifc, monitor)
        if not high_func:
            continue
        try:
            candidates.extend(scanFunc(func, high_func, language_id, bits, in_main, image_range))
        except:
            continue
    return rankCandidates(candidates)


def getAttackInitFunc(func_mgr, ifc, monitor, main_func):
    attack_init_func = None
    language_id = currentProgram.getLanguageID().toString()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        entry_point = func.getEntryPoint()
        refs = getReferencesTo(entry_point)
        # attack_init() only called by main() and Entry Point
        if len(refs) == 0:
            continue
        cand_caller_funcs = []
        for ref in refs:
            cand_caller_func = None
            # in some cases (sh4), getFunctionContaining cannot identify function correctly
            if language_id == ARCH_SH4:
                cand_caller_func = getFunctionBefore(ref.getFromAddress())
            else:
                cand_caller_func = getFunctionContaining(ref.getFromAddress())
            # dont append Entry Point and self function
            if cand_caller_func and cand_caller_func != func:
                cand_caller_funcs.append(cand_caller_func)
        cand_caller_funcs = list(set(cand_caller_funcs))
        # in some cases (mips), ghidra doesnt handle xref correctly
        if language_id not in (ARCH_MIPS_BE, ARCH_MIPS_LE):
            if len(cand_caller_funcs) != 1:
                continue
            if cand_caller_funcs[0] != main_func:
                continue
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        # dont include if/while statements
        match = re.search(r"(if|while) \(.+?\)", ccode.toString())
        if match:
            continue
        # include return 1; statements
        match = re.search(r"return 1;", ccode.toString())
        if not match:
            continue
        lines = ccode.toString().split(";")
        # attack_init() has more than 5 lines
        if len(lines) >= 5:
            attack_init_func = func
            break
    return attack_init_func


def getAttacks(func_mgr, ifc, monitor, attack_init_func):
    attacks = []
    func_names = [func.getName() for func in func_mgr.getFunctions(True)]
    ccode = getDecompileCCode(attack_init_func, ifc, monitor)
    if not ccode:
        return None
    lines = re.split(r"[;{}]", ccode.toString())
    vector = func_name = None
    for line in lines:
        # ; *(undefined *)(ppcVar1 + 1) = 0 ; *(code *)(ppcVar2 + 1) = (code)0x2
        vec_mobj = re.match(r".+? = (\(.+\)|)([0-9a-fA-F|x]+)$", line)
        if vec_mobj:
            vector = int(vec_mobj.group(2), 0)
        # ; *ppcVar1 = attack_udp_generic
        func_mobj = re.match(r".+? = ([0-9a-zA-Z|_]+)$", line)
        if func_mobj:
            tmp_func_name = func_mobj.group(1)
            if tmp_func_name in func_names:
                func_name = tmp_func_name
        # save vector and attack func
        if vector is not None and func_name is not None:
            func = getGlobalFunctions(func_name)[0]
            attack = collections.OrderedDict()
            attack[KEY_VECTOR] = vector
            attack[KEY_NAME] = func.getName()
            attack[KEY_ENTRYPOINT] = func.getEntryPoint().toString()
            attacks.append(attack)
            vector = func_name = None
    if attacks:
        return attacks
    # get vector and attack func from add_attack() (optimization level is not -O3)
    vector = func_name = None
    for line in lines:
        # ; add_attack(0,attack_udp_generic)
        add_mobj = re.match(r"[0-9a-zA-Z|_]+\(([0-9a-fA-F|x]+),([0-9a-zA-Z|_]+)\)$", line)
        if add_mobj:
            vector = int(add_mobj.group(1), 0)
            tmp_func_name = add_mobj.group(2)
            if tmp_func_name in func_names:
                func_name = tmp_func_name
            # save vector and attack func
            if vector is not None and func_name is not None:
                func = getGlobalFunctions(func_name)[0]
                attack = collections.OrderedDict()
                attack[KEY_VECTOR] = vector
                attack[KEY_NAME] = func.getName()
                attack[KEY_ENTRYPOINT] = func.getEntryPoint().toString()
                attacks.append(attack)
                vector = func_name = None
    return attacks


def getUByte(addr):
    return getByte(addr) & 0xFF


def getDecompileCCode(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    ccode = res.getCCodeMarkup()
    if not ccode:
        return None
    return ccode


def selfTest():
    """runnable under CPython: python ghidra_scripts/parse_main.py"""
    # countCloseSeq must agree with the regex it replaces
    old_re = r".+?\(0\);.+?\(1\);.+?\(2\);"
    cases = [
        "  close(0);\n  close(1);\n  close(2);",          # separate lines: no match
        "  close(0); close(1); close(2);",                # the real daemonize line
        "x(0);y(1);z(2);",
        "(0);(1);(2);",                                   # nothing before (0);
        "a(0);(1);(2);",                                  # nothing between (0); and (1);
        "a(0);b(1);c(2); a(0);b(1);c(2);",                # two sequences
        "a(0);b(2);c(1);",                                # wrong order
        "",
        "a(0);b(1);",                                     # incomplete
        "int main(void)\n{\n  close(0); close(1); close(2);\n  while( true ) {\n",
        # the leading .+? means a match can start at a *later* (0); occurrence
        "(0);(1);(2);;1(0);a(1);b(2);",
        "(0);(0);(1);(1);(1);a(2);",
        ]
    for text in cases:
        assert countCloseSeq(text) == len(re.findall(old_re, text)), repr(text)
    # IZ1H9: _DAT_00512644 = 0x5f3447a7 written straight to memory on x86-64
    assert bytesToIp(toNetworkBytes(0x5f3447a7, 4, ORDER_MEMORY, ARCH_X86_64)) == "167.71.52.95"
    # boatnet: htonl(0xb5d663b4) on ARM LE
    assert bytesToIp(toNetworkBytes(0xb5d663b4, 4, ORDER_WRAPPER, ARCH_ARM_LE)) == "181.214.99.180"
    # big endian program, straight memory write
    assert bytesToIp(toNetworkBytes(0xb5d663b4, 4, ORDER_MEMORY, ARCH_MIPS_BE)) == "181.214.99.180"
    # ARM:BE:32:v8 behaves like LE here, matching getCnc()
    assert bytesToIp(toNetworkBytes(0x5f3447a7, 4, ORDER_MEMORY, ARCH_ARM_BE)) == "167.71.52.95"
    # ports
    port_bytes = toNetworkBytes(0x1700, 2, ORDER_MEMORY, ARCH_X86_64)
    assert (port_bytes[0] << 8) | port_bytes[1] == 23
    port_bytes = toNetworkBytes(0x46d1, 2, ORDER_WRAPPER, ARCH_ARM_LE)
    assert (port_bytes[0] << 8) | port_bytes[1] == 18129
    # IZ1H9 on ARM splits sin_port into two byte stores: 0x00 then 0x17
    byte_writes = {(GROUP_ABS, 0x23bd2): [(0x00, 1, ORDER_MEMORY, None)],
                   (GROUP_ABS, 0x23bd3): [(0x17, 1, ORDER_MEMORY, None)]}
    assert _portFromWrites(byte_writes, GROUP_ABS, 0x23bd0, ARCH_ARM_LE) == 23
    assert _portFromWrites({}, GROUP_ABS, 0x23bd0, ARCH_ARM_LE) is None
    # validation
    assert not isGlobalUnicast(toNetworkBytes(0x0100007f, 4, ORDER_MEMORY, ARCH_X86_64))  # 127.0.0.1
    assert not isGlobalUnicast([0, 0, 0, 0])
    assert not isGlobalUnicast([192, 168, 1, 1])
    assert not isGlobalUnicast([239, 1, 1, 1])
    assert isGlobalUnicast([167, 71, 52, 95])
    assert not isGlobalUnicast([9, 0, 0, 0])
    assert not isGlobalUnicast([1, 2, 3, 0])
    # 0x805a341 is a pointer into a 32-bit x86 image, not 8.5.163.65
    assert looksLikeAddress(0x805a341, (0x8048000, 0x805f000))
    assert not looksLikeAddress(0x5f3447a7, (0x400000, 0x520000))
    # roles
    assert classifyRole("8.8.8.8", PORT_DNS) == ROLE_RESOLVER
    assert classifyRole("1.2.3.4", PORT_SINGLE_INSTANCE) == ROLE_BIND
    assert classifyRole("1.2.3.4", 23) == ROLE_CNC
    # ranking: resolver never wins, duplicates collapse
    ranked = rankCandidates([
        makeCandidate("8.8.8.8", PORT_DNS, ROLE_RESOLVER, "f", "0", "0x0", ORDER_MEMORY, "0x0", True),
        makeCandidate("167.71.52.95", 23, ROLE_CNC, "f", "0", "0x0", ORDER_MEMORY, "0x0", True),
        makeCandidate("167.71.52.95", 23, ROLE_CNC, "g", "0", "0x0", ORDER_MEMORY, "0x0", False),
        ])
    assert len(ranked) == 2
    assert ranked[0][KEY_IP] == "167.71.52.95" and ranked[0][KEY_BEST]
    assert ranked[0][KEY_FUNC] == "f"
    assert ranked[1][KEY_BEST] is False
    # a bare address with no port and no connect call is never promoted
    weak = rankCandidates([makeCandidate("8.5.163.65", None, ROLE_CNC, "f", "0", "0x0", ORDER_WRAPPER, "0x0")])
    assert weak[0][KEY_BEST] is False
    strong = rankCandidates([makeCandidate("8.5.163.65", None, ROLE_CNC, "f", "0", "0x0", ORDER_WRAPPER, "0x0", False, True)])
    assert strong[0][KEY_BEST] is True
    print("selfTest: ok")


if __name__ == "__main__" and not HAS_GHIDRA:
    selfTest()
elif __name__ == "__main__":
    language_id = currentProgram.getLanguageID().toString()
    if language_id not in LANGS:
        print("error: this script only target for " + str(LANGS))
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()
    ifc = DecompInterface()
    _ = ifc.setOptions(DecompileOptions())
    _ = ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    main_func = main_ccode = None
    resolve_cnc_addr_func = cnc = attack_init_func = attacks = None
    main_func, main_ccode = getMainFunc(func_mgr, ifc, monitor)
    main_how = "heuristic" if main_func else None
    if main_func and main_ccode:
        resolve_cnc_addr_func, cnc = getResolveCncAddrFunc(listing, func_mgr, ifc, monitor, main_func, main_ccode)
        attack_init_func = getAttackInitFunc(func_mgr, ifc, monitor, main_func)
        if attack_init_func:
            attacks = getAttacks(func_mgr, ifc, monitor, attack_init_func)
    # the sockaddr_in scan does not need main_ccode, so it can also run on a
    # main found through __libc_start_main, or with no main at all
    if not main_func:
        main_func = getMainFuncByLibcStart(func_mgr, ifc, monitor)
        main_how = "libc_start_main" if main_func else None
    cnc_immediates = getCncImmediates(func_mgr, ifc, monitor, main_func, language_id)
    # make results data
    output_dict = collections.OrderedDict()
    output_dict[KEY_SCRIPT_NAME] = SCRIPT_NAME
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM] = collections.OrderedDict()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_NAME] = currentProgram.getName()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_PATH] = currentProgram.getExecutablePath()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_SHA256] = currentProgram.getExecutableSHA256()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_LANGUAGE_ID] = language_id
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_IMAGE_BASE] = currentProgram.getImageBase().toString()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_MIN_ADDR] = currentProgram.getMinAddress().toString()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_MAX_ADDR] = currentProgram.getMaxAddress().toString()
    if main_func:
        output_dict[KEY_MAIN_FUNC] = collections.OrderedDict()
        output_dict[KEY_MAIN_FUNC][KEY_NAME] = main_func.getName()
        output_dict[KEY_MAIN_FUNC][KEY_ENTRYPOINT] = main_func.getEntryPoint().toString()
        output_dict[KEY_MAIN_FUNC][KEY_HOW] = main_how
    if resolve_cnc_addr_func:
        output_dict[KEY_RESOLVE_CNC_ADDR_FUNC] = collections.OrderedDict()
        output_dict[KEY_RESOLVE_CNC_ADDR_FUNC][KEY_NAME] = resolve_cnc_addr_func.getName()
        output_dict[KEY_RESOLVE_CNC_ADDR_FUNC][KEY_ENTRYPOINT] = resolve_cnc_addr_func.getEntryPoint().toString()
        output_dict[KEY_RESOLVE_CNC_ADDR_FUNC][KEY_CNC] = cnc
    if attack_init_func:
        output_dict[KEY_ATTACK_INIT_FUNC] = collections.OrderedDict()
        output_dict[KEY_ATTACK_INIT_FUNC][KEY_NAME] = attack_init_func.getName()
        output_dict[KEY_ATTACK_INIT_FUNC][KEY_ENTRYPOINT] = attack_init_func.getEntryPoint().toString()
    if attacks:
        output_dict[KEY_ATTACK_INIT_FUNC][KEY_ATTACKS_COUNT] = len(attacks)
        output_dict[KEY_ATTACK_INIT_FUNC][KEY_ATTACKS] = []
        for attack in attacks:
            output_dict[KEY_ATTACK_INIT_FUNC][KEY_ATTACKS].append(attack)
    if cnc_immediates:
        output_dict[KEY_CNC_IMMEDIATES] = cnc_immediates
    # output results to stdout/jsonfile
    args = ghidra_app.getScriptArgs()
    if len(args) < 1:
        print("")
        print("")
        print(json.dumps(output_dict, ensure_ascii=False, indent=2))
        print("")
        print("")
    else:
        output_file = args[0]
        with open(output_file, "w") as f:
            json.dump(output_dict, f, ensure_ascii=False, indent=2)
