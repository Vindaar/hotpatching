## This follows
## https://nullprogram.com/blog/2016/03/31/
## essentially.

import posix
type
  Instr {.union.} = object
    bytes: array[8, byte]
    value: uint64

proc hotpatchImpl*(target, replacement: pointer) =
  # YOLO who needs alignment
  #doAssert (cast[ByteAddress](target) and ByteAddress(0x07)) == 0
  var page = cast[pointer](cast[ByteAddress](target) and (not 0xfff))
  doAssert mprotect(page, 4096, PROT_WRITE or PROT_EXEC) == 0
  let rel = cast[ByteAddress](replacement) - cast[ByteAddress](target) - 5
  var instr = Instr(bytes: [0xe9.byte,
                            (rel shr 0).byte,
                            (rel shr 8).byte,
                            (rel shr 16).byte,
                            (rel shr 24).byte,
                            0, 0, 0])
  cast[ptr uint64](target)[] = instr.value
  doAssert mprotect(page, 4096, PROT_EXEC) == 0

template hotpatch*(target, replacement: typed): untyped =
  ## Hot-patches the given `target` function (must be a function symbol) by
  ## the function symbol `replacement`. Affects your whole program. :)
  hotpatchImpl(cast[pointer](target), cast[pointer](replacement))
