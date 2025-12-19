import std/strutils
import jsony
import ../types/session
from ../../types import Session, SessionKind

proc safeParseBiggestInt(s: string): int64 =
  try:
    result = parseBiggestInt(s)
  except ValueError:
    result = 0

proc parseSession*(raw: string): Session =
  let session = raw.fromJson(RawSession)
  let kind = if session.kind == "": "oauth" else: session.kind

  case kind
  of "oauth":
    let dashPos = session.oauthToken.find('-')
    let id = if dashPos > 0: session.oauthToken[0 ..< dashPos] else: ""
    let parsedId = safeParseBiggestInt(id)
    result = Session(
      kind: SessionKind.oauth,
      id: parsedId,
      username: session.username,
      oauthToken: session.oauthToken,
      oauthSecret: session.oauthTokenSecret
    )
  of "cookie":
    let parsedId = safeParseBiggestInt(session.id)
    result = Session(
      kind: SessionKind.cookie,
      id: parsedId,
      username: session.username,
      authToken: session.authToken,
      ct0: session.ct0
    )
  else:
    raise newException(ValueError, "Unknown session kind: " & kind)
