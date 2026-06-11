{ zstd-fpc: Zstandard (RFC 8878) written in Pascal.
  Copyright (c) 2026 @fibodevy / https://github.com/fibodevy/zstd-fpc
  MIT licensed (see LICENSE). Free to use and modify; keep this notice
  and the link when you redistribute the sources. }

unit zstddecoder;

{ Zstandard (RFC 8878) decoder written in Pascal from the format
  specification. Decodes anything a standard zstd encoder emits:

    * frames: full header parsing (window descriptor, single-segment,
      content size, checksum flag), multiple concatenated frames,
      skippable frames, xxhash64 content checksum verification
    * blocks: raw, RLE, compressed
    * literals: raw, RLE, Huffman (1 or 4 streams), treeless reuse of
      the previous tree; tree descriptions both direct (4-bit nibbles)
      and FSE-compressed (two interleaved states, shared table)
    * sequences: predefined / RLE / FSE / repeat coding tables for the
      three channels (literal lengths, offsets, match lengths), repeat
      offsets with the literals_length=0 shift rule

  External dictionaries are not supported (frames demanding a
  dictionary ID are rejected with ZSTD_E_DICTIONARY).

  Streaming API, feed any chunking you like:
    var d := TZstdDecoder.Create;
    d.Init;
    d.Update(p, n); ... drain d.buf / d.ResetBuf ...
    d.Finalize;     // verifies the tail; check d.err
    d.Free;

  One-shot:
    data := ZstdUnpack(packed);  // nil + ZstdLastError <> 0 on damage

  No external units are referenced (the System unit is implicit). }

{$mode unleashed}
{$ifndef ZSTD_CHECKS}{$R-}{$Q-}{$endif}

interface

type
  TByteArray = array of Byte;

  { progress callback: receives 0..100 (percent of totalbytes produced;
    only fires when the frame header declares its content size) }
  TZstdProgressProc = reference to procedure(percent: Integer);

const
  ZSTD_OK           = 0;
  ZSTD_E_MAGIC      = 1;   // first bytes are not a zstandard frame
  ZSTD_E_HEADER     = 2;   // malformed frame header
  ZSTD_E_WINDOW     = 3;   // frame wants a window above the accepted limit
  ZSTD_E_DICTIONARY = 4;   // frame requires an external dictionary
  ZSTD_E_BLOCK      = 5;   // bad block header / reserved block type
  ZSTD_E_LITERALS   = 6;   // corrupt literals section
  ZSTD_E_HUFFMAN    = 7;   // corrupt huffman tree or huffman stream
  ZSTD_E_FSE        = 8;   // corrupt fse table description
  ZSTD_E_SEQUENCES  = 9;   // corrupt sequences section
  ZSTD_E_OFFSET     = 10;  // match offset beyond decoded history
  ZSTD_E_CHECKSUM   = 11;  // content checksum mismatch
  ZSTD_E_TRUNCATED  = 12;  // input ended in the middle of a frame
  ZSTD_E_SIZE       = 13;  // decoded size contradicts the frame header

type
  { one row of an FSE decoding table: emitted symbol + state transition }
  TFseCell = packed record
    sym: Byte;
    bits: Byte;
    base: Word;
  end;

  TFseTable = record
    accLog: Integer;
    live: Boolean;
    cells: array of TFseCell;
  end;

  { huffman lookup cell, table is indexed by the next maxBits of stream }
  THufCell = packed record
    sym: Byte;
    len: Byte;
  end;
  THufTable = array of THufCell;

  TZstdDecoder = class
  private
    // input accumulator
    inbuf: TByteArray;
    inlen, rpos: SizeInt;
    // state machine
    stage: Integer;
    skipLeft: QWord;          // bytes left of a skippable frame
    finished: Boolean;
    maxWindow: SizeInt;
    // current frame
    windowSize: SizeInt;
    blockMax: SizeInt;
    fcsKnown: Boolean;
    fcs: QWord;
    hasChecksum: Boolean;
    lastBlock: Boolean;
    blockType: Integer;
    blockLen: SizeInt;        // header field (content len, or RLE count)
    frameOut: QWord;          // bytes produced by the current frame
    frameBase: SizeInt;       // where the current frame starts inside buf
    dictReach: SizeInt;       // dictionary bytes below the frame start
    reps: array[0..2] of SizeInt;
    // entropy state carried between blocks of one frame
    hufTab: THufTable;
    hufBits: Integer;
    hufLive: Boolean;
    tabLL, tabOF, tabML: TFseTable;
    // dictionary, applies to every frame until the next Init
    dictSet: Boolean;
    dictId: LongWord;
    dictBody: TByteArray;     // content part, the virtual window prefix
    dictHufTab: THufTable;
    dictHufBits: Integer;
    dictHufLive: Boolean;
    dictLL, dictOF, dictML: TFseTable;
    dictReps: array[0..2] of SizeInt;
    // history kept after ResetBuf (window tail, oldest first; with a
    // dictionary loaded its content sits at the bottom)
    hist: TByteArray;
    histLen: SizeInt;
    // literals scratch
    lits: TByteArray;
    // xxhash64 of produced content
    xxV: array[0..3] of QWord;
    xxTail: array[0..31] of Byte;
    xxCnt: Integer;
    xxTotal: QWord;
    // progress
    progCb: TZstdProgressProc;
    lastPct: Integer;
    procedure fail(code: Integer);
    function avail: SizeInt; inline;
    function pIn(at: SizeInt): PByte; inline;
    procedure consume(n: SizeInt); inline;
    function process: Boolean;
    function parseHeader: Boolean;
    function decodeBlock: Boolean;
    function decodeLiterals(p: PByte; len: SizeInt; out litLen: SizeInt;
      out used: SizeInt): Boolean;
    function readTree(p: PByte; len: SizeInt; out used: SizeInt;
      var tab: THufTable; out bits: Integer): Boolean;
    function hufStream(p: PByte; len: SizeInt; dst: PByte;
      count: SizeInt): Boolean;
    procedure outGrow(extra: SizeInt);
    procedure xxReset;
    procedure xxFeed(p: PByte; len: SizeInt);
    function xxDigest: QWord;
    procedure report;
  public
    buf: TByteArray;          // accumulated decoded output
    buflen: SizeInt;          // number of valid bytes in buf
    err: Integer;             // ZSTD_OK or first ZSTD_E_* hit
    totalbytes: QWord;        // declared content size of the first frame, if known

    procedure Init(AMaxWindow: SizeInt = 128 * 1024 * 1024);
    procedure onProgress(ACallback: TZstdProgressProc);
    { call between Init and the first Update; accepts both raw-content
      blobs (any bytes, min 8) and structured dictionaries written by
      zstd trainers (magic EC30A437: id, entropy tables, content) }
    procedure UseDictionary(Data: Pointer; Len: SizeInt); overload;
    procedure UseDictionary(const Data: array of Byte); overload;
    procedure Update(Data: Pointer; Len: SizeInt); overload;
    procedure Update(const Data: array of Byte); overload;
    procedure Finalize;
    procedure ResetBuf;
  end;

var
  ZstdLastError: Integer = 0;

{ one-shot helpers; on damaged input return nil and set ZstdLastError }
function ZstdUnpack(Data: Pointer; Len: SizeInt; AMaxWindow: SizeInt = 128 * 1024 * 1024): TByteArray; overload;
function ZstdUnpack(const Source: array of Byte; AMaxWindow: SizeInt = 128 * 1024 * 1024): TByteArray; overload;
function ZstdUnpack(Data: Pointer; Len: SizeInt; Dict: Pointer; DictLen: SizeInt; AMaxWindow: SizeInt = 128 * 1024 * 1024): TByteArray; overload;
function ZstdUnpack(const Source: array of Byte; const Dict: array of Byte; AMaxWindow: SizeInt = 128 * 1024 * 1024): TByteArray; overload;
{ string variants: compressed bytes in a string, decoded text out (a distinct name avoids the AnsiString/array-of-byte overload clash) }
function ZstdUnpackStr(const Source: String; AMaxWindow: SizeInt = 128 * 1024 * 1024): String; overload;
function ZstdUnpackStr(const Source: String; const Dict: String; AMaxWindow: SizeInt = 128 * 1024 * 1024): String; overload;

implementation

const
  MAGIC_FRAME = $FD2FB528;
  MAGIC_SKIP_LO = $184D2A50;
  MAGIC_SKIP_HI = $184D2A5F;
  MAGIC_DICT = $EC30A437;
  BLOCK_CAP = 128 * 1024;

  // stages of the input state machine
  sgMagic = 0;
  sgHeader = 1;
  sgBlockHead = 2;
  sgBlockBody = 3;
  sgChecksum = 4;
  sgSkipSize = 5;
  sgSkipData = 6;

  // baseline + extra-bit count per literals-length code
  LL_BASE: array[0..35] of LongWord = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536);
  LL_XTRA: array[0..35] of Byte = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16);

  // baseline + extra-bit count per match-length code
  ML_BASE: array[0..52] of LongWord = (
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
    4099, 8195, 16387, 32771, 65539);
  ML_XTRA: array[0..52] of Byte = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16);

  // default distributions (spec: "Default Distributions")
  DEF_LL: array[0..35] of SmallInt = (
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1);
  DEF_ML: array[0..52] of SmallInt = (
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1);
  DEF_OF: array[0..28] of SmallInt = (
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1);

  XXP1 = QWord($9E3779B185EBCA87);
  XXP2 = QWord($C2B2AE3D27D4EB4F);
  XXP3 = QWord($165667B19E3779F9);
  XXP4 = QWord($85EBCA77C2B2AE63);
  XXP5 = QWord($27D4EB2F165667C5);

var
  defLL, defOF, defML: TFseTable;   // built once from the distributions above

function bitTop(v: LongWord): Integer; inline;
begin
  result := BsrDWord(v);   // caller guarantees v <> 0
end;

{ ---------------------------------------------------------------- }
{ backward bit reader: zstd entropy payloads are written forward    }
{ but consumed from the last byte down. The final byte carries a    }
{ sentinel 1-bit above 0..7 padding zeroes.                         }
{ ---------------------------------------------------------------- }

type
  TTailBits = record
    p: PByte;
    bytesBelow: SizeInt;      // whole bytes not yet pulled into acc
    acc: QWord;               // low cnt bits = top of remaining stream
    cnt: Integer;
    bad: Boolean;
    procedure Open(data: PByte; len: SizeInt);
    function BitsLeft: SizeInt; inline;
    procedure Pull(n: Integer); inline;
    function PeekPad(n: Integer): LongWord; inline;
    procedure Drop(n: Integer); inline;
    function Take(n: Integer): LongWord; inline;     // exact, bad on underrun
    function TakePad(n: Integer): LongWord; inline;  // zero-padded variant
  end;

procedure TTailBits.Open(data: PByte; len: SizeInt);
var
  last: Byte;
begin
  p := data;
  acc := 0;
  cnt := 0;
  bytesBelow := 0;
  bad := (len <= 0);
  if bad then exit;
  last := data[len - 1];
  if last = 0 then begin
    bad := true;
    exit;
  end;
  cnt := bitTop(last);                  // bits below the sentinel
  acc := last and ((1 shl cnt) - 1);
  bytesBelow := len - 1;
end;

function TTailBits.BitsLeft: SizeInt;
begin
  result := bytesBelow * 8 + cnt;
end;

procedure TTailBits.Pull(n: Integer);
begin
  while (cnt < n) and (bytesBelow > 0) do begin
    Dec(bytesBelow);
    acc := (acc shl 8) or p[bytesBelow];
    Inc(cnt, 8);
  end;
end;

function TTailBits.PeekPad(n: Integer): LongWord;
begin
  if n = 0 then exit(0);
  Pull(n);
  if cnt >= n then
    result := (acc shr (cnt - n)) and ((QWord(1) shl n) - 1)
  else
    result := (acc shl (n - cnt)) and ((QWord(1) shl n) - 1);
end;

procedure TTailBits.Drop(n: Integer);
begin
  if n > cnt then begin       // Pull was done by the peek; cnt is all we have
    bad := true;
    cnt := 0;
    acc := 0;
    exit;
  end;
  Dec(cnt, n);
  acc := acc and ((QWord(1) shl cnt) - 1);
end;

function TTailBits.Take(n: Integer): LongWord;
begin
  if n = 0 then exit(0);
  Pull(n);
  if cnt < n then begin
    bad := true;
    exit(0);
  end;
  result := (acc shr (cnt - n)) and ((QWord(1) shl n) - 1);
  Dec(cnt, n);
  acc := acc and ((QWord(1) shl cnt) - 1);
end;

function TTailBits.TakePad(n: Integer): LongWord;
begin
  result := PeekPad(n);
  if cnt >= n then
    Drop(n)
  else begin                  // consumed into the padding zone
    cnt := 0;
    acc := 0;
  end;
end;

{ ---------------------------------------------------------------- }
{ forward bit reader for FSE table descriptions                     }
{ ---------------------------------------------------------------- }

type
  THeadBits = record
    p: PByte;
    len, bytePos: SizeInt;
    acc: QWord;
    cnt: Integer;
    procedure Open(data: PByte; alen: SizeInt);
    function Take(n: Integer): LongWord; inline;
    function Peek(n: Integer): LongWord; inline;
    procedure Drop(n: Integer); inline;
    function BytesUsed: SizeInt;
    function Overran: Boolean;
  end;

procedure THeadBits.Open(data: PByte; alen: SizeInt);
begin
  p := data;
  len := alen;
  bytePos := 0;
  acc := 0;
  cnt := 0;
end;

function THeadBits.Peek(n: Integer): LongWord;
begin
  while (cnt < n) and (bytePos < len) do begin
    acc := acc or (QWord(p[bytePos]) shl cnt);
    Inc(bytePos);
    Inc(cnt, 8);
  end;
  result := acc and ((QWord(1) shl n) - 1);   // zero-padded past the end
end;

procedure THeadBits.Drop(n: Integer);
begin
  acc := acc shr n;
  Dec(cnt, n);                // may go negative: that means overrun
end;

function THeadBits.Take(n: Integer): LongWord;
begin
  result := Peek(n);
  Drop(n);
end;

function THeadBits.BytesUsed: SizeInt;
begin
  result := (bytePos * 8 - cnt + 7) div 8;
end;

function THeadBits.Overran: Boolean;
begin
  result := bytePos * 8 - cnt > len * 8;
end;

{ ---------------------------------------------------------------- }
{ FSE: distribution parsing and decoding-table construction         }
{ ---------------------------------------------------------------- }

{ parse a serialized probability distribution; returns false on damage.
  norm[] gets -1..tableSize entries, used = bytes eaten from p. }
function fseReadSpec(p: PByte; len: SizeInt; maxAcc, maxSym: Integer; out norm: array of SmallInt; out accLog: Integer; out used: SizeInt): Boolean;
var
  rd: THeadBits;
  remain, sym, bits, small, v, val, rep: Integer;
begin
  result := false;
  if len < 1 then exit;
  rd.Open(p, len);
  accLog := Integer(rd.Take(4)) + 5;
  if accLog > maxAcc then exit;
  remain := (1 shl accLog) + 1;
  sym := 0;
  for var i := 0 to maxSym do
    norm[i] := 0;
  while remain > 1 do begin
    if sym > maxSym then exit;
    // field width for values 0..remain, low values save one bit
    bits := bitTop(LongWord(remain)) + 1;
    small := (1 shl bits) - 1 - remain;
    v := Integer(rd.Peek(bits));
    if (v and ((1 shl (bits - 1)) - 1)) < small then begin
      val := v and ((1 shl (bits - 1)) - 1);
      rd.Drop(bits - 1);
    end
    else begin
      rd.Drop(bits);
      if v < (1 shl (bits - 1)) then
        val := v
      else
        val := v - small;
    end;
    val := val - 1;                       // probability; -1 is "less than 1"
    if val >= 0 then begin
      norm[sym] := val;
      Dec(remain, val);
      Inc(sym);
      if val = 0 then begin               // run-length flags for zero probs
        repeat
          rep := Integer(rd.Take(2));
          for var i := 1 to rep do begin
            if sym > maxSym then exit;
            norm[sym] := 0;
            Inc(sym);
          end;
        until rep <> 3;
      end;
    end
    else begin
      norm[sym] := -1;
      Dec(remain);
      Inc(sym);
    end;
  end;
  if (remain <> 1) or rd.Overran then exit;
  used := rd.BytesUsed;
  result := true;
end;

{ build the decoding table from a normalized distribution }
function fseBuild(var t: TFseTable; const norm: array of SmallInt; nSym, accLog: Integer): Boolean;
var
  size, mask, step, pos, hiCells, present, nxt: Integer;
  counter: array[0..255] of Word;
begin
  result := false;
  size := 1 shl accLog;
  t.accLog := accLog;
  t.live := false;
  if Length(t.cells) <> size then
    SetLength(t.cells, size);
  // "less than 1" symbols take single cells at the very top
  hiCells := 0;
  present := 0;
  for var s := 0 to nSym - 1 do begin
    if norm[s] <> 0 then Inc(present);
    if norm[s] = -1 then begin
      Inc(hiCells);
      t.cells[size - hiCells].sym := s;
      counter[s] := 1;
    end
    else
      counter[s] := norm[s];
  end;
  if present < 2 then exit;
  // spread the regular symbols
  step := (size shr 1) + (size shr 3) + 3;
  mask := size - 1;
  pos := 0;
  for var s := 0 to nSym - 1 do
    for var i := 1 to norm[s] do begin
      t.cells[pos].sym := s;
      repeat
        pos := (pos + step) and mask;
      until pos < size - hiCells;
    end;
  if pos <> 0 then exit;
  // per-cell transition: walking states in order visits each symbol's
  // cells in ascending state order, which is exactly the rank needed
  for var u := 0 to size - 1 do begin
    nxt := counter[t.cells[u].sym];
    Inc(counter[t.cells[u].sym]);
    t.cells[u].bits := accLog - bitTop(nxt);
    t.cells[u].base := (nxt shl t.cells[u].bits) - size;
  end;
  t.live := true;
  result := true;
end;

procedure fseRle(var t: TFseTable; sym: Byte);
begin
  t.accLog := 0;
  SetLength(t.cells, 1);
  t.cells[0].sym := sym;
  t.cells[0].bits := 0;
  t.cells[0].base := 0;
  t.live := true;
end;

procedure buildDefaults;
begin
  if defLL.live then exit;
  fseBuild(defLL, DEF_LL, 36, 6);
  fseBuild(defOF, DEF_OF, 29, 5);
  fseBuild(defML, DEF_ML, 53, 6);
end;

{ ---------------------------------------------------------------- }
{ xxhash64 (streaming), for the optional content checksum           }
{ ---------------------------------------------------------------- }

{$push}{$Q-}  // hash arithmetic wraps mod 2^64 by design

function rol64(x: QWord; n: Integer): QWord; inline;
begin
  result := (x shl n) or (x shr (64 - n));
end;

function xxRound(acc, v: QWord): QWord; inline;
begin
  result := rol64(acc + v * XXP2, 31) * XXP1;
end;

procedure TZstdDecoder.xxReset;
begin
  xxV[0] := QWord($60EA27EEADC0B5D6);   // XXP1 + XXP2 (mod 2^64)
  xxV[1] := XXP2;
  xxV[2] := 0;
  xxV[3] := QWord($61C8864E7A143579);   // 0 - XXP1   (mod 2^64)
  xxCnt := 0;
  xxTotal := 0;
end;

procedure TZstdDecoder.xxFeed(p: PByte; len: SizeInt);
var
  take: SizeInt;
begin
  if not hasChecksum then exit;
  Inc(xxTotal, len);
  while len > 0 do begin
    if (xxCnt = 0) and (len >= 32) then begin
      // full stripes straight from the source
      repeat
        xxV[0] := xxRound(xxV[0], PQWord(p)[0]);
        xxV[1] := xxRound(xxV[1], PQWord(p)[1]);
        xxV[2] := xxRound(xxV[2], PQWord(p)[2]);
        xxV[3] := xxRound(xxV[3], PQWord(p)[3]);
        Inc(p, 32);
        Dec(len, 32);
      until len < 32;
      if len = 0 then exit;
    end;
    take := 32 - xxCnt;
    if take > len then take := len;
    Move(p^, xxTail[xxCnt], take);
    Inc(xxCnt, take);
    Inc(p, take);
    Dec(len, take);
    if xxCnt = 32 then begin
      xxV[0] := xxRound(xxV[0], PQWord(@xxTail[0])^);
      xxV[1] := xxRound(xxV[1], PQWord(@xxTail[8])^);
      xxV[2] := xxRound(xxV[2], PQWord(@xxTail[16])^);
      xxV[3] := xxRound(xxV[3], PQWord(@xxTail[24])^);
      xxCnt := 0;
    end;
  end;
end;

function TZstdDecoder.xxDigest: QWord;
var
  h: QWord;
  i: Integer;
begin
  if xxTotal >= 32 then begin
    h := rol64(xxV[0], 1) + rol64(xxV[1], 7) + rol64(xxV[2], 12) +
      rol64(xxV[3], 18);
    h := (h xor xxRound(0, xxV[0])) * XXP1 + XXP4;
    h := (h xor xxRound(0, xxV[1])) * XXP1 + XXP4;
    h := (h xor xxRound(0, xxV[2])) * XXP1 + XXP4;
    h := (h xor xxRound(0, xxV[3])) * XXP1 + XXP4;
  end
  else
    h := XXP5;
  h := h + xxTotal;
  i := 0;
  while i + 8 <= xxCnt do begin
    h := rol64(h xor xxRound(0, PQWord(@xxTail[i])^), 27) * XXP1 + XXP4;
    Inc(i, 8);
  end;
  if i + 4 <= xxCnt then begin
    h := rol64(h xor (QWord(PLongWord(@xxTail[i])^) * XXP1), 23) * XXP2 + XXP3;
    Inc(i, 4);
  end;
  while i < xxCnt do begin
    h := rol64(h xor (xxTail[i] * XXP5), 11) * XXP1;
    Inc(i);
  end;
  h := h xor (h shr 33);
  h := h * XXP2;
  h := h xor (h shr 29);
  h := h * XXP3;
  h := h xor (h shr 32);
  result := h;
end;

{$pop}

{ ---------------------------------------------------------------- }
{ TZstdDecoder                                                      }
{ ---------------------------------------------------------------- }

procedure TZstdDecoder.Init(AMaxWindow: SizeInt);
begin
  buildDefaults;
  inbuf := nil;
  inlen := 0;
  rpos := 0;
  buf := nil;
  buflen := 0;
  hist := nil;
  histLen := 0;
  err := ZSTD_OK;
  stage := sgMagic;
  finished := false;
  maxWindow := AMaxWindow;
  totalbytes := 0;
  progCb := nil;
  lastPct := -1;
  windowSize := 0;
  blockMax := 0;
  frameOut := 0;
  frameBase := 0;
  dictReach := 0;
  hasChecksum := false;
  fcsKnown := false;
  hufLive := false;
  tabLL.live := false;
  tabOF.live := false;
  tabML.live := false;
  dictSet := false;
  dictId := 0;
  dictBody := nil;
  dictHufLive := false;
  dictLL.live := false;
  dictOF.live := false;
  dictML.live := false;
  SetLength(lits, BLOCK_CAP);
end;

procedure TZstdDecoder.UseDictionary(Data: Pointer; Len: SizeInt);
var
  p: PByte;
  at, used: SizeInt;
  norm: array[0..63] of SmallInt;
  acc: Integer;
  csize: SizeInt;
begin
  if finished then exit;
  dictSet := false;
  dictHufLive := false;
  dictLL.live := false;
  dictOF.live := false;
  dictML.live := false;
  dictId := 0;
  dictReps[0] := 1;
  dictReps[1] := 4;
  dictReps[2] := 8;
  p := Data;
  if Len < 8 then begin
    fail(ZSTD_E_DICTIONARY);
    exit;
  end;
  if PLongWord(p)^ = MAGIC_DICT then begin
    // structured dictionary: id, entropy tables, recent offsets, content
    dictId := PLongWord(p + 4)^;
    if dictId = 0 then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    at := 8;
    if not readTree(p + at, Len - at, used, dictHufTab, dictHufBits)
    then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    dictHufLive := true;
    Inc(at, used);
    // tables ship in offsets, match lengths, literal lengths order
    if not (fseReadSpec(p + at, Len - at, 8, 31, norm, acc, used) and
      fseBuild(dictOF, norm, 32, acc)) then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    Inc(at, used);
    if not (fseReadSpec(p + at, Len - at, 9, 52, norm, acc, used) and
      fseBuild(dictML, norm, 53, acc)) then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    Inc(at, used);
    if not (fseReadSpec(p + at, Len - at, 9, 35, norm, acc, used) and
      fseBuild(dictLL, norm, 36, acc)) then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    Inc(at, used);
    if Len - at < 12 then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
    csize := Len - at - 12;
    for var i := 0 to 2 do begin
      dictReps[i] := PLongWord(p + at)^;
      Inc(at, 4);
      if (dictReps[i] = 0) or (dictReps[i] > csize) then begin
        fail(ZSTD_E_DICTIONARY);
        exit;
      end;
    end;
    SetLength(dictBody, csize);
    if csize > 0 then
      Move(p[at], dictBody[0], csize);
  end
  else begin
    // raw content: the whole blob becomes the window prefix
    SetLength(dictBody, Len);
    Move(p^, dictBody[0], Len);
  end;
  dictSet := true;
end;

procedure TZstdDecoder.UseDictionary(const Data: array of Byte);
begin
  if Length(Data) > 0 then
    UseDictionary(@Data[0], Length(Data))
  else
    fail(ZSTD_E_DICTIONARY);
end;

procedure TZstdDecoder.onProgress(ACallback: TZstdProgressProc);
begin
  progCb := ACallback;
end;

procedure TZstdDecoder.fail(code: Integer);
begin
  if err = ZSTD_OK then err := code;
  finished := true;
end;

function TZstdDecoder.avail: SizeInt;
begin
  result := inlen - rpos;
end;

function TZstdDecoder.pIn(at: SizeInt): PByte;
begin
  result := @inbuf[rpos + at];
end;

procedure TZstdDecoder.consume(n: SizeInt);
begin
  Inc(rpos, n);
end;

procedure TZstdDecoder.report;
var
  pct: Integer;
begin
  if (progCb = nil) or (totalbytes = 0) then exit;
  if frameOut >= totalbytes then
    pct := 100
  else
    pct := Integer((frameOut * 100) div totalbytes);
  if pct <> lastPct then begin
    lastPct := pct;
    progCb(pct);
  end;
end;

procedure TZstdDecoder.outGrow(extra: SizeInt);
var
  want: SizeInt;
begin
  want := buflen + extra;
  if want <= Length(buf) then exit;
  if want < 2 * Length(buf) then want := 2 * Length(buf);
  if want < 256 * 1024 then want := 256 * 1024;
  SetLength(buf, want);
end;

procedure TZstdDecoder.Update(Data: Pointer; Len: SizeInt);
begin
  if finished or (Len <= 0) then exit;
  // compact the input accumulator
  if rpos = inlen then begin
    rpos := 0;
    inlen := 0;
  end
  else if rpos > 4 * 1024 * 1024 then begin
    Move(inbuf[rpos], inbuf[0], inlen - rpos);
    Dec(inlen, rpos);
    rpos := 0;
  end;
  if inlen + Len > Length(inbuf) then
    SetLength(inbuf, inlen + Len + 64 * 1024);
  Move(Data^, inbuf[inlen], Len);
  Inc(inlen, Len);
  while (not finished) and process do ;
end;

procedure TZstdDecoder.Update(const Data: array of Byte);
begin
  if Length(Data) > 0 then Update(@Data[0], Length(Data));
end;

procedure TZstdDecoder.Finalize;
begin
  if finished then exit;
  while (not finished) and process do ;
  if err <> ZSTD_OK then exit;
  if (stage <> sgMagic) or (avail > 0) then
    fail(ZSTD_E_TRUNCATED)
  else
    finished := true;
end;

procedure TZstdDecoder.ResetBuf;
var
  need, fromBuf, fromHist: SizeInt;
  tmp: TByteArray;
begin
  // after draining, everything future match copies may reach must stay:
  // the window tail, plus the dictionary while it is still reachable;
  // sources: old hist (dict + previously drained) + the current buf
  if frameOut <= QWord(windowSize) then
    need := SizeInt(frameOut) + dictReach
  else
    need := windowSize;
  if stage in [sgMagic, sgSkipSize, sgSkipData] then need := 0;
  fromBuf := buflen - frameBase;     // only this frame's bytes count
  if fromBuf > need then fromBuf := need;
  fromHist := need - fromBuf;
  if fromHist > histLen then fromHist := histLen;
  tmp := nil;
  SetLength(tmp, fromHist + fromBuf);
  if fromHist > 0 then
    Move(hist[histLen - fromHist], tmp[0], fromHist);
  if fromBuf > 0 then
    Move(buf[buflen - fromBuf], tmp[fromHist], fromBuf);
  hist := tmp;
  histLen := fromHist + fromBuf;
  buflen := 0;
  frameBase := 0;
end;

{ frame header; returns false when more input is needed }
function TZstdDecoder.parseHeader: Boolean;
var
  fhd: Byte;
  fcsFlag, didSize, hdrLen, off: Integer;
  single: Boolean;
  wb: Byte;
  ws: QWord;
begin
  result := false;
  if avail < 1 then exit;
  fhd := pIn(0)^;
  fcsFlag := fhd shr 6;
  single := (fhd and $20) <> 0;
  if (fhd and $08) <> 0 then begin   // reserved bit
    fail(ZSTD_E_HEADER);
    exit;
  end;
  hasChecksum := (fhd and $04) <> 0;
  case fhd and 3 of
    0: didSize := 0;
    1: didSize := 1;
    2: didSize := 2;
    else didSize := 4;
  end;
  hdrLen := 1 + didSize;
  if not single then Inc(hdrLen);
  case fcsFlag of
    0: if single then Inc(hdrLen, 1);
    1: Inc(hdrLen, 2);
    2: Inc(hdrLen, 4);
    3: Inc(hdrLen, 8);
  end;
  if avail < hdrLen then exit;       // wait for the full header
  off := 1;
  ws := 0;
  if not single then begin
    wb := pIn(off)^;
    Inc(off);
    ws := QWord(1) shl (10 + (wb shr 3));
    ws := ws + (ws shr 3) * (wb and 7);
  end;
  if didSize > 0 then begin
    var did: LongWord := 0;
    for var i := 0 to didSize - 1 do
      did := did or (LongWord(pIn(off + i)^) shl (8 * i));
    Inc(off, didSize);
    // a non-zero id demands the matching dictionary; id 0 means none
    if (did <> 0) and ((not dictSet) or (did <> dictId)) then begin
      fail(ZSTD_E_DICTIONARY);
      exit;
    end;
  end;
  fcsKnown := (fcsFlag <> 0) or single;
  fcs := 0;
  case fcsFlag of
    0: if single then fcs := pIn(off)^;
    1: fcs := (QWord(pIn(off)^) or (QWord(pIn(off + 1)^) shl 8)) + 256;
    2: begin
      for var i := 0 to 3 do
        fcs := fcs or (QWord(pIn(off + i)^) shl (8 * i));
    end;
    3: begin
      for var i := 0 to 7 do
        fcs := fcs or (QWord(pIn(off + i)^) shl (8 * i));
    end;
  end;
  if single then ws := fcs;
  if ws > QWord(maxWindow) then begin
    fail(ZSTD_E_WINDOW);
    exit;
  end;
  windowSize := SizeInt(ws);
  blockMax := windowSize;
  if blockMax > BLOCK_CAP then blockMax := BLOCK_CAP;
  consume(hdrLen);
  // fresh frame state; a loaded dictionary provides the starting
  // entropy tables, recent offsets and the window prefix
  frameOut := 0;
  frameBase := buflen;
  reps[0] := 1;
  reps[1] := 4;
  reps[2] := 8;
  hufLive := false;
  tabLL.live := false;
  tabOF.live := false;
  tabML.live := false;
  histLen := 0;
  if dictSet then begin
    reps[0] := dictReps[0];
    reps[1] := dictReps[1];
    reps[2] := dictReps[2];
    if dictHufLive then begin
      hufTab := dictHufTab;
      hufBits := dictHufBits;
      hufLive := true;
    end;
    if dictLL.live then tabLL := dictLL;
    if dictOF.live then tabOF := dictOF;
    if dictML.live then tabML := dictML;
    histLen := Length(dictBody);
    if histLen > 0 then begin
      if Length(hist) < histLen then SetLength(hist, histLen);
      Move(dictBody[0], hist[0], histLen);
    end;
  end;
  dictReach := histLen;
  xxReset;
  if fcsKnown and (totalbytes = 0) then totalbytes := fcs;
  stage := sgBlockHead;
  result := true;
end;

{ huffman tree description; builds tab/bits. used = bytes eaten }
function TZstdDecoder.readTree(p: PByte; len: SizeInt; out used: SizeInt; var tab: THufTable; out bits: Integer): Boolean;
var
  weights: array[0..255] of Byte;
  norm: array[0..15] of SmallInt;
  nw, accLog, maxBits, lastW: Integer;
  descLen: SizeInt;
  ft: TFseTable;
  rd: TTailBits;
  sum, p2, rest: LongWord;
  s1, s2: Integer;
  fseLen: SizeInt;
begin
  result := false;
  used := 0;
  if len < 1 then exit;
  nw := 0;
  if p^ >= 128 then begin
    // direct: two 4-bit weights a byte
    nw := p^ - 127;
    if 1 + (nw + 1) div 2 > len then exit;
    for var i := 0 to nw - 1 do begin
      if (i and 1) = 0 then
        weights[i] := p[1 + i div 2] shr 4
      else
        weights[i] := p[1 + i div 2] and 15;
    end;
    used := 1 + (nw + 1) div 2;
  end
  else begin
    // FSE-compressed weights: one shared table, two interleaved states
    fseLen := p^;
    if 1 + fseLen > len then exit;
    if not fseReadSpec(p + 1, fseLen, 6, 15, norm, accLog, descLen) then exit;
    ft.live := false;
    ft.cells := nil;
    if not fseBuild(ft, norm, 16, accLog) then exit;
    rd.Open(p + 1 + descLen, fseLen - descLen);
    if rd.bad then exit;
    s1 := Integer(rd.Take(accLog));
    s2 := Integer(rd.Take(accLog));
    if rd.bad then exit;
    while true do begin
      if nw > 254 then exit;
      weights[nw] := ft.cells[s1].sym;
      Inc(nw);
      if rd.BitsLeft < ft.cells[s1].bits then begin
        if nw > 254 then exit;
        weights[nw] := ft.cells[s2].sym;
        Inc(nw);
        break;
      end;
      s1 := ft.cells[s1].base + Integer(rd.TakePad(ft.cells[s1].bits));
      if nw > 254 then exit;
      weights[nw] := ft.cells[s2].sym;
      Inc(nw);
      if rd.BitsLeft < ft.cells[s2].bits then begin
        if nw > 254 then exit;
        weights[nw] := ft.cells[s1].sym;
        Inc(nw);
        break;
      end;
      s2 := ft.cells[s2].base + Integer(rd.TakePad(ft.cells[s2].bits));
    end;
    used := 1 + fseLen;
  end;
  // complete to a power of two with the implicit final weight
  sum := 0;
  for var i := 0 to nw - 1 do begin
    if weights[i] > 11 then exit;
    if weights[i] > 0 then
      sum := sum + (LongWord(1) shl (weights[i] - 1));
  end;
  if sum = 0 then exit;
  maxBits := bitTop(sum) + 1;
  p2 := LongWord(1) shl maxBits;
  rest := p2 - sum;
  if (rest and (rest - 1)) <> 0 then exit;   // must be a power of two
  lastW := bitTop(rest) + 1;
  if (maxBits > 11) or (nw >= 256) then exit;
  weights[nw] := lastW;
  Inc(nw);
  // canonical table fill: shortest weights first = lowest indexes
  begin
    var minW: Integer := 12;
    var nz: Integer := 0;
    for var i := 0 to nw - 1 do
      if weights[i] > 0 then begin
        Inc(nz);
        if weights[i] < minW then minW := weights[i];
      end;
    if (nz < 2) or (minW <> 1) then exit;
  end;
  bits := maxBits;
  SetLength(tab, 1 shl maxBits);   // also un-shares a dictionary table
  begin
    var cur: Integer := 0;
    for var w := 1 to maxBits do
      for var s := 0 to nw - 1 do begin
        if weights[s] <> w then continue;
        var span: Integer := 1 shl (w - 1);
        for var k := 0 to span - 1 do begin
          tab[cur + k].sym := s;
          tab[cur + k].len := maxBits + 1 - w;
        end;
        Inc(cur, span);
      end;
    if cur <> 1 shl maxBits then exit;
  end;
  result := true;
end;

{ decode one huffman bitstream into count literals }
function TZstdDecoder.hufStream(p: PByte; len: SizeInt; dst: PByte; count: SizeInt): Boolean;
var
  rd: TTailBits;
  cell: THufCell;
begin
  result := false;
  rd.Open(p, len);
  if rd.bad then exit;
  for var i := 0 to count - 1 do begin
    cell := hufTab[rd.PeekPad(hufBits)];
    rd.Drop(cell.len);
    if rd.bad then exit;
    dst[i] := cell.sym;
  end;
  result := rd.BitsLeft = 0;   // must land exactly on the first useful bit
end;

{ literals section of one compressed block; fills lits[0..litLen) }
function TZstdDecoder.decodeLiterals(p: PByte; len: SizeInt; out litLen: SizeInt; out used: SizeInt): Boolean;
var
  b0: Byte;
  sf, hdr, streams: Integer;
  regen, comp: SizeInt;
  v: QWord;
  treeUsed, area, per, lastN: SizeInt;
  q: PByte;
  s1, s2, s3, s4: SizeInt;
begin
  result := false;
  litLen := 0;
  used := 0;
  if len < 1 then exit;
  b0 := p^;
  sf := (b0 shr 2) and 3;
  case b0 and 3 of
    0, 1: begin                       // raw / rle
      case sf of
        0, 2: begin
          regen := b0 shr 3;
          hdr := 1;
        end;
        1: begin
          if len < 2 then exit;
          regen := (b0 shr 4) or (SizeInt(p[1]) shl 4);
          hdr := 2;
        end;
        else begin
          if len < 3 then exit;
          regen := (b0 shr 4) or (SizeInt(p[1]) shl 4) or
            (SizeInt(p[2]) shl 12);
          hdr := 3;
        end;
      end;
      if regen > BLOCK_CAP then exit;
      if (b0 and 3) = 0 then begin
        if hdr + regen > len then exit;
        Move(p[hdr], lits[0], regen);
        used := hdr + regen;
      end
      else begin
        if hdr + 1 > len then exit;
        FillChar(lits[0], regen, p[hdr]);
        used := hdr + 1;
      end;
      litLen := regen;
      exit(true);
    end;
  end;
  // huffman-coded literals, with or without a fresh tree
  case sf of
    0, 1: begin
      if len < 3 then exit;
      v := QWord(b0) or (QWord(p[1]) shl 8) or (QWord(p[2]) shl 16);
      regen := (v shr 4) and 1023;
      comp := (v shr 14) and 1023;
      hdr := 3;
    end;
    2: begin
      if len < 4 then exit;
      v := QWord(b0) or (QWord(p[1]) shl 8) or (QWord(p[2]) shl 16) or
        (QWord(p[3]) shl 24);
      regen := (v shr 4) and 16383;
      comp := (v shr 18) and 16383;
      hdr := 4;
    end;
    else begin
      if len < 5 then exit;
      v := QWord(b0) or (QWord(p[1]) shl 8) or (QWord(p[2]) shl 16) or
        (QWord(p[3]) shl 24) or (QWord(p[4]) shl 32);
      regen := (v shr 4) and $3FFFF;
      comp := (v shr 22) and $3FFFF;
      hdr := 5;
    end;
  end;
  if sf = 0 then streams := 1 else streams := 4;
  if (regen > BLOCK_CAP) or (hdr + comp > len) then exit;
  q := p + hdr;
  treeUsed := 0;
  if (b0 and 3) = 2 then begin
    if not readTree(q, comp, treeUsed, hufTab, hufBits) then exit;
    hufLive := true;
  end
  else if not hufLive then exit;      // treeless without a previous tree
  area := comp - treeUsed;
  q := q + treeUsed;
  if streams = 1 then begin
    if not hufStream(q, area, @lits[0], regen) then exit;
  end
  else begin
    if area < 10 then exit;
    s1 := SizeInt(q[0]) or (SizeInt(q[1]) shl 8);
    s2 := SizeInt(q[2]) or (SizeInt(q[3]) shl 8);
    s3 := SizeInt(q[4]) or (SizeInt(q[5]) shl 8);
    s4 := area - 6 - s1 - s2 - s3;
    if (s4 < 1) then exit;
    per := (regen + 3) div 4;
    lastN := regen - 3 * per;
    if lastN < 0 then exit;
    q := q + 6;
    if not hufStream(q, s1, @lits[0], per) then exit;
    if not hufStream(q + s1, s2, @lits[per], per) then exit;
    if not hufStream(q + s1 + s2, s3, @lits[2 * per], per) then exit;
    if not hufStream(q + s1 + s2 + s3, s4, @lits[3 * per], lastN) then exit;
  end;
  litLen := regen;
  used := hdr + comp;
  result := true;
end;

{ one complete compressed block; input bytes pIn(0)..pIn(blockLen) }
function TZstdDecoder.decodeBlock: Boolean;
var
  p: PByte;
  litLen, litUsed, seqLen: SizeInt;
  nbSeq: Integer;
  here: SizeInt;
  modes: Byte;
  norm: array[0..63] of SmallInt;
  accLog: Integer;
  specUsed: SizeInt;
  rd: TTailBits;
  stLL, stOF, stML: Integer;
  llCode, mlCode, ofCode: Integer;
  ofValue: QWord;
  ll, ml: SizeInt;
  offset, src: SizeInt;
  litPos: SizeInt;
  produced: SizeInt;
  blockStart: SizeInt;

  function loadTable(var t: TFseTable; mode: Integer; maxSym, maxAcc: Integer;
    const def: TFseTable): Boolean;
  begin
    result := false;
    case mode of
      0: t := def;
      1: begin                       // rle: single symbol byte
        if here >= seqLen then exit;
        if p[here] > maxSym then exit;
        fseRle(t, p[here]);
        Inc(here);
      end;
      2: begin                       // fresh fse table
        if not fseReadSpec(p + here, seqLen - here, maxAcc, maxSym, norm,
          accLog, specUsed) then exit;
        // table must not alias the shared default instances
        if Pointer(t.cells) = Pointer(def.cells) then t.cells := nil;
        if not fseBuild(t, norm, maxSym + 1, accLog) then exit;
        Inc(here, specUsed);
      end;
      else if not t.live then exit;  // repeat without a previous table
    end;
    result := true;
  end;

begin
  result := false;
  p := pIn(0);
  blockStart := buflen;
  if not decodeLiterals(p, blockLen, litLen, litUsed) then begin
    fail(ZSTD_E_LITERALS);
    exit;
  end;
  seqLen := blockLen - litUsed;
  p := p + litUsed;
  if seqLen < 1 then begin
    fail(ZSTD_E_SEQUENCES);
    exit;
  end;
  // sequence count
  here := 0;
  if p[0] < 128 then begin
    nbSeq := p[0];
    here := 1;
  end
  else if p[0] < 255 then begin
    if seqLen < 2 then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    nbSeq := ((p[0] - 128) shl 8) + p[1];
    here := 2;
  end
  else begin
    if seqLen < 3 then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    nbSeq := p[1] + (Integer(p[2]) shl 8) + $7F00;
    here := 3;
  end;
  outGrow(blockMax);
  if nbSeq = 0 then begin
    // block is its literals, nothing else allowed in the section
    if here <> seqLen then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    if litLen > blockMax then begin
      fail(ZSTD_E_SIZE);
      exit;
    end;
    if litLen > 0 then begin
      Move(lits[0], buf[buflen], litLen);
      Inc(buflen, litLen);
      Inc(frameOut, litLen);
      xxFeed(@buf[blockStart], buflen - blockStart);
    end;
    consume(blockLen);
    exit(true);
  end;
  if here >= seqLen then begin
    fail(ZSTD_E_SEQUENCES);
    exit;
  end;
  modes := p[here];
  Inc(here);
  if (modes and 3) <> 0 then begin
    fail(ZSTD_E_SEQUENCES);
    exit;
  end;
  if not loadTable(tabLL, (modes shr 6) and 3, 35, 9, defLL) then begin
    fail(ZSTD_E_FSE);
    exit;
  end;
  if not loadTable(tabOF, (modes shr 4) and 3, 31, 8, defOF) then begin
    fail(ZSTD_E_FSE);
    exit;
  end;
  if not loadTable(tabML, (modes shr 2) and 3, 52, 9, defML) then begin
    fail(ZSTD_E_FSE);
    exit;
  end;
  rd.Open(p + here, seqLen - here);
  if rd.bad then begin
    fail(ZSTD_E_SEQUENCES);
    exit;
  end;
  stLL := Integer(rd.Take(tabLL.accLog));
  stOF := Integer(rd.Take(tabOF.accLog));
  stML := Integer(rd.Take(tabML.accLog));
  litPos := 0;
  produced := 0;
  for var n := 0 to nbSeq - 1 do begin
    llCode := tabLL.cells[stLL].sym;
    ofCode := tabOF.cells[stOF].sym;
    mlCode := tabML.cells[stML].sym;
    if (llCode > 35) or (mlCode > 52) or (ofCode > 31) then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    ofValue := (QWord(1) shl ofCode) + rd.Take(ofCode);
    ml := ML_BASE[mlCode] + rd.Take(ML_XTRA[mlCode]);
    ll := LL_BASE[llCode] + rd.Take(LL_XTRA[llCode]);
    if rd.bad then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    // resolve the offset through the repeat history
    if ofValue > 3 then begin
      offset := SizeInt(ofValue - 3);
      reps[2] := reps[1];
      reps[1] := reps[0];
      reps[0] := offset;
    end
    else begin
      var ri: Integer := Integer(ofValue) - 1;
      if ll = 0 then Inc(ri);
      if ri = 0 then
        offset := reps[0]
      else if ri < 3 then begin
        offset := reps[ri];
        if ri = 2 then reps[2] := reps[1];
        reps[1] := reps[0];
        reps[0] := offset;
      end
      else begin
        offset := reps[0] - 1;
        if offset <= 0 then begin
          fail(ZSTD_E_OFFSET);
          exit;
        end;
        reps[2] := reps[1];
        reps[1] := reps[0];
        reps[0] := offset;
      end;
    end;
    // copy literals
    if (litPos + ll > litLen) or (produced + ll + ml > blockMax) then begin
      fail(ZSTD_E_SEQUENCES);
      exit;
    end;
    if ll > 0 then begin
      Move(lits[litPos], buf[buflen], ll);
      Inc(litPos, ll);
      Inc(buflen, ll);
      Inc(frameOut, ll);
      Inc(produced, ll);
    end;
    // copy the match; reachable history is the frame output plus,
    // until the output exceeds the window, the whole dictionary
    begin
      var reach: QWord;
      if frameOut <= QWord(windowSize) then
        reach := frameOut + QWord(dictReach)
      else
        reach := QWord(windowSize);
      if QWord(offset) > reach then begin
        fail(ZSTD_E_OFFSET);
        exit;
      end;
    end;
    src := buflen - offset;
    if src >= frameBase then begin
      if offset >= ml then begin
        Move(buf[src], buf[buflen], ml);
        Inc(buflen, ml);
      end
      else
        for var k := 1 to ml do begin
          buf[buflen] := buf[buflen - offset];
          Inc(buflen);
        end;
    end
    else begin
      // source starts below the frame: dictionary / drained history
      for var k := 1 to ml do begin
        if src < frameBase then
          buf[buflen] := hist[histLen + (src - frameBase)]
        else
          buf[buflen] := buf[src];
        Inc(src);
        Inc(buflen);
      end;
    end;
    Inc(frameOut, ml);
    Inc(produced, ml);
    // advance the three states, except after the final sequence
    if n <> nbSeq - 1 then begin
      stLL := tabLL.cells[stLL].base + Integer(rd.Take(tabLL.cells[stLL].bits));
      stML := tabML.cells[stML].base + Integer(rd.Take(tabML.cells[stML].bits));
      stOF := tabOF.cells[stOF].base + Integer(rd.Take(tabOF.cells[stOF].bits));
      if rd.bad then begin
        fail(ZSTD_E_SEQUENCES);
        exit;
      end;
    end;
  end;
  if rd.bad or (rd.BitsLeft <> 0) then begin
    fail(ZSTD_E_SEQUENCES);
    exit;
  end;
  // trailing literals
  ll := litLen - litPos;
  if produced + ll > blockMax then begin
    fail(ZSTD_E_SIZE);
    exit;
  end;
  if ll > 0 then begin
    Move(lits[litPos], buf[buflen], ll);
    Inc(buflen, ll);
    Inc(frameOut, ll);
  end;
  if buflen > blockStart then
    xxFeed(@buf[blockStart], buflen - blockStart);
  consume(blockLen);
  result := true;
end;

{ drive the state machine; false = need more input (or finished) }
function TZstdDecoder.process: Boolean;
var
  v: LongWord;
  bh: LongWord;
  n: SizeInt;
begin
  result := false;
  if finished then exit;
  case stage of
    sgMagic: begin
      if avail < 4 then exit;
      v := PLongWord(pIn(0))^;
      if v = MAGIC_FRAME then begin
        consume(4);
        stage := sgHeader;
        result := true;
      end
      else if (v >= MAGIC_SKIP_LO) and (v <= MAGIC_SKIP_HI) then begin
        consume(4);
        stage := sgSkipSize;
        result := true;
      end
      else
        fail(ZSTD_E_MAGIC);
    end;
    sgHeader:
      result := parseHeader;
    sgSkipSize: begin
      if avail < 4 then exit;
      skipLeft := PLongWord(pIn(0))^;
      consume(4);
      stage := sgSkipData;
      result := true;
    end;
    sgSkipData: begin
      n := avail;
      if QWord(n) > skipLeft then n := SizeInt(skipLeft);
      consume(n);
      Dec(skipLeft, n);
      if skipLeft = 0 then begin
        stage := sgMagic;
        result := true;
      end;
    end;
    sgBlockHead: begin
      if avail < 3 then exit;
      bh := LongWord(pIn(0)^) or (LongWord(pIn(1)^) shl 8) or
        (LongWord(pIn(2)^) shl 16);
      consume(3);
      lastBlock := (bh and 1) <> 0;
      blockType := (bh shr 1) and 3;
      blockLen := bh shr 3;
      if blockType = 3 then begin
        fail(ZSTD_E_BLOCK);
        exit;
      end;
      // size limits: both content and decoded size obey blockMax
      if blockLen > blockMax then begin
        fail(ZSTD_E_BLOCK);
        exit;
      end;
      stage := sgBlockBody;
      result := true;
    end;
    sgBlockBody: begin
      case blockType of
        0: begin                       // raw
          if avail < blockLen then exit;
          if blockLen > 0 then begin
            outGrow(blockLen);
            Move(pIn(0)^, buf[buflen], blockLen);
            xxFeed(pIn(0), blockLen);
            Inc(buflen, blockLen);
            Inc(frameOut, blockLen);
          end;
          consume(blockLen);
        end;
        1: begin                       // rle
          if avail < 1 then exit;
          if blockLen > 0 then begin
            outGrow(blockLen);
            FillChar(buf[buflen], blockLen, pIn(0)^);
            xxFeed(@buf[buflen], blockLen);
            Inc(buflen, blockLen);
            Inc(frameOut, blockLen);
          end;
          consume(1);
        end;
        else begin                     // compressed
          if blockLen < 1 then begin
            fail(ZSTD_E_BLOCK);
            exit;
          end;
          if avail < blockLen then exit;
          if not decodeBlock then exit;
        end;
      end;
      report;
      if lastBlock then begin
        if fcsKnown and (frameOut <> fcs) then begin
          fail(ZSTD_E_SIZE);
          exit;
        end;
        if hasChecksum then
          stage := sgChecksum
        else
          stage := sgMagic;
      end
      else
        stage := sgBlockHead;
      result := true;
    end;
    sgChecksum: begin
      if avail < 4 then exit;
      v := PLongWord(pIn(0))^;
      consume(4);
      if v <> LongWord(xxDigest and $FFFFFFFF) then begin
        fail(ZSTD_E_CHECKSUM);
        exit;
      end;
      stage := sgMagic;
      result := true;
    end;
  end;
end;

{ ---------------------------------------------------------------- }
{ one-shot helpers                                                  }
{ ---------------------------------------------------------------- }

function ZstdUnpack(Data: Pointer; Len: SizeInt; AMaxWindow: SizeInt): TByteArray;
begin
  result := nil;
  ZstdLastError := ZSTD_OK;
  var d := autofree TZstdDecoder.Create;
  d.Init(AMaxWindow);
  d.Update(Data, Len);
  d.Finalize;
  if d.err <> ZSTD_OK then begin
    ZstdLastError := d.err;
    exit;
  end;
  SetLength(result, d.buflen);
  if d.buflen > 0 then Move(d.buf[0], result[0], d.buflen);
end;

function ZstdUnpack(const Source: array of Byte; AMaxWindow: SizeInt): TByteArray;
begin
  if Length(Source) = 0 then begin
    ZstdLastError := ZSTD_OK;
    exit(nil);
  end;
  result := ZstdUnpack(@Source[0], Length(Source), AMaxWindow);
end;

function ZstdUnpack(Data: Pointer; Len: SizeInt; Dict: Pointer; DictLen: SizeInt; AMaxWindow: SizeInt): TByteArray;
begin
  result := nil;
  ZstdLastError := ZSTD_OK;
  var d := autofree TZstdDecoder.Create;
  d.Init(AMaxWindow);
  d.UseDictionary(Dict, DictLen);
  d.Update(Data, Len);
  d.Finalize;
  if d.err <> ZSTD_OK then begin
    ZstdLastError := d.err;
    exit;
  end;
  SetLength(result, d.buflen);
  if d.buflen > 0 then
    Move(d.buf[0], result[0], d.buflen);
end;

function ZstdUnpack(const Source: array of Byte; const Dict: array of Byte; AMaxWindow: SizeInt): TByteArray;
begin
  result := nil;
  ZstdLastError := ZSTD_E_DICTIONARY;
  if (Length(Source) = 0) or (Length(Dict) = 0) then exit;
  result := ZstdUnpack(@Source[0], Length(Source), @Dict[0], Length(Dict), AMaxWindow);
end;

function ZstdUnpackStr(const Source: String; AMaxWindow: SizeInt): String;
var
  r: TByteArray;
begin
  result := '';
  if Length(Source) = 0 then begin
    ZstdLastError := ZSTD_OK;
    exit;
  end;
  r := ZstdUnpack(@Source[1], Length(Source), AMaxWindow);
  SetLength(result, Length(r));
  if Length(r) > 0 then Move(r[0], result[1], Length(r));
end;

function ZstdUnpackStr(const Source: String; const Dict: String; AMaxWindow: SizeInt): String;
var
  r: TByteArray;
begin
  result := '';
  ZstdLastError := ZSTD_E_DICTIONARY;
  if (Length(Source) = 0) or (Length(Dict) = 0) then exit;
  r := ZstdUnpack(@Source[1], Length(Source), @Dict[1], Length(Dict), AMaxWindow);
  SetLength(result, Length(r));
  if Length(r) > 0 then Move(r[0], result[1], Length(r));
end;

end.
