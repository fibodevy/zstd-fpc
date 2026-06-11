{ zstd-fpc: Zstandard (RFC 8878) written in Pascal.
  Copyright (c) 2026 @fibodevy / https://github.com/fibodevy/zstd-fpc
  MIT licensed (see LICENSE). Free to use and modify; keep this notice
  and the link when you redistribute the sources. }

unit zstdencoder;

{ Zstandard (RFC 8878) encoder written in Pascal from the format
  specification. Output decodes with any standard zstd decoder.

  What it emits:
    * frames: single-segment headers with exact content size for
      buffered inputs, window-descriptor headers for streamed input of
      unknown size, optional xxhash64 content checksum
    * blocks: raw / RLE / compressed, picked by measured size
    * literals: raw, RLE, or Huffman (1 or 4 streams); code lengths are
      built with package-merge, so they are optimal under the 11-bit
      format limit; the tree ships as direct nibbles or FSE-compressed
      weights, whichever is shorter
    * sequences: literal lengths, offsets and match lengths coded with
      predefined / RLE / fresh FSE tables, chosen per channel by cost;
      repeat-offset codes with the literals_length=0 shift rule

  Matching: hash-chain searcher with byte-3 shortcut, repeat-offset
  probes and one-step lazy evaluation; effort scales with level 1..9
  (window 512K..16M, chain depth 4..128).

  Streaming API:
    var c := TZstdEncoder.Create;
    c.Init(7);                  // level, optional checksum flag
    c.Update(p, n);  ... drain c.buf / c.ResetBuf ...  c.Finalize;
    c.Free;

  One-shot:
    packed := ZstdPack(data);        // level 6
    packed := ZstdPack(data, 9);

  No external units are referenced (the System unit is implicit). }

{$mode unleashed}
{$ifndef ZSTD_CHECKS}{$R-}{$Q-}{$endif}

interface

type
  TByteArray = array of Byte;

  { progress callback: receives 0..100 (percent of totalbytes consumed;
    set totalbytes yourself when streaming) }
  TZstdProgressProc = reference to procedure(percent: Integer);

  { an FSE coding table: per-symbol transforms + rank-to-state map }
  TFseEnc = record
    accLog: Integer;
    stateTab: array of Word;          // rank -> next state value
    dBits: array of Integer;          // per symbol
    dState: array of Integer;
  end;

  TZstdEncoder = class
  private
    // parameters
    level: Integer;
    withSum: Boolean;
    wlog, tries, niceLen: Integer;
    doLazy: Boolean;
    // frame
    started, done: Boolean;
    winSize: SizeInt;
    blockCap: SizeInt;           // max decompressed bytes per block
    consumed: QWord;             // input bytes taken from the caller
    // window: retained back-reference data + still-unprocessed input
    win: TByteArray;
    winLen: SizeInt;
    procPos: SizeInt;            // start of unprocessed data inside win
    // match finder
    head: array of SizeInt;      // hash4 chain heads, -1 empty
    head3: array of SizeInt;     // hash3 single-slot heads
    chain: array of SizeInt;
    chainMask: SizeInt;
    insPos: SizeInt;             // next win position to index
    hbits: Integer;
    reps: array[0..2] of SizeInt;
    // per-block scratch
    litBuf: TByteArray;
    litCnt: SizeInt;
    seqLL, seqML, seqOV: array of LongWord;
    seqCnt: Integer;
    scratch: TByteArray;         // assembled compressed block body
    litSec: TByteArray;          // assembled literals section
    // entropy state shared with the decoder across blocks of one frame
    pHufLen: array[0..255] of Byte;
    pHufCode: array[0..255] of Word;
    pHufLive: Boolean;
    pSeqEnc: array[0..2] of TFseEnc;        // LL / OF / ML
    pSeqNorm: array[0..2, 0..63] of SmallInt;
    pSeqAcc: array[0..2] of Integer;
    pSeqKind: array[0..2] of Integer;       // 0 none, 1 table, 2 rle
    pSeqRle: array[0..2] of Byte;
    // dictionary staged by UseDictionary, applied in startFrame
    dictId: LongWord;
    dictPrefix: SizeInt;          // dictionary bytes at the start of win
    framePosBase: SizeInt;        // frame position of win[0] (can be <0)
    dictHasEntropy: Boolean;
    dictHufLen: array[0..255] of Byte;
    dictHufCode: array[0..255] of Word;
    dictNorm: array[0..2, 0..63] of SmallInt;
    dictAcc: array[0..2] of Integer;
    dictReps: array[0..2] of SizeInt;
    // xxhash64 of consumed input
    xxV: array[0..3] of QWord;
    xxTail: array[0..31] of Byte;
    xxCnt: Integer;
    xxTotal: QWord;
    // progress
    progCb: TZstdProgressProc;
    lastPct: Integer;
    procedure emit(const src; n: SizeInt);
    procedure emitByte(b: Byte); inline;
    procedure startFrame(knownSize: Boolean; size: QWord);
    procedure slideWindow;
    procedure indexUpTo(limit: SizeInt);
    function maxDistAt(p: SizeInt): SizeInt; inline;
    function bestMatch(p, srcEnd: SizeInt; out dist: SizeInt): Integer;
    function bestRep(p, srcEnd: SizeInt; out ri: Integer): Integer;
    procedure parseBlock(srcEnd: SizeInt);
    procedure pushSeq(ll, ml, ofv: LongWord);
    procedure flushBlock(srcLen: SizeInt; isLast: Boolean);
    function buildLiterals: SizeInt;
    function buildSequences(dst: TByteArray; at: SizeInt): SizeInt;
    procedure compressStep(final: Boolean);
    procedure xxReset;
    procedure xxFeed(p: PByte; len: SizeInt);
    function xxDigest: QWord;
    procedure report;
  public
    buf: TByteArray;             // accumulated compressed output
    buflen: SizeInt;             // valid bytes in buf
    err: Integer;                // 0 = ok, 1 = unusable dictionary
    totalbytes: QWord;           // expected input size, drives onProgress
    // optional histogram capture (dictionary training plumbing)
    statsOn: Boolean;
    statSeqs: QWord;
    statLit: array[0..255] of QWord;
    statLL: array[0..35] of QWord;
    statOF: array[0..31] of QWord;
    statML: array[0..52] of QWord;

    procedure Init(ALevel: Integer = 6; AChecksum: Boolean = true);
    procedure onProgress(ACallback: TZstdProgressProc);
    { call between Init and the first Update; accepts raw-content blobs and structured dictionaries (the same kinds the decoder takes) }
    procedure UseDictionary(Data: Pointer; Len: SizeInt); overload;
    procedure UseDictionary(const Data: array of Byte); overload;
    procedure Update(Data: Pointer; Len: SizeInt); overload;
    procedure Update(const Data: array of Byte); overload;
    procedure Finalize;
    procedure ResetBuf;
  end;

{ one-shot helpers }
function ZstdPack(Data: Pointer; Len: SizeInt; ALevel: Integer = 6; AChecksum: Boolean = true): TByteArray; overload;
function ZstdPack(const Source: array of Byte; ALevel: Integer = 6; AChecksum: Boolean = true): TByteArray; overload;
function ZstdPack(Data: Pointer; Len: SizeInt; Dict: Pointer; DictLen: SizeInt; ALevel: Integer = 6; AChecksum: Boolean = true): TByteArray; overload;
function ZstdPack(const Source: array of Byte; const Dict: array of Byte; ALevel: Integer = 6; AChecksum: Boolean = true): TByteArray; overload;
{ string variants: plaintext in, compressed bytes packed in a string (a distinct name avoids the AnsiString/array-of-byte overload clash) }
function ZstdPackStr(const Source: String; ALevel: Integer = 6; AChecksum: Boolean = true): String; overload;
function ZstdPackStr(const Source: String; const Dict: String; ALevel: Integer = 6; AChecksum: Boolean = true): String; overload;

{ assemble a structured dictionary from content + symbol histograms; the trainer in zstdtrainer.pas feeds this. nil when not encodable }
function ZstdBuildDictionary(const content: array of Byte; const litFreq: array of LongWord; const llFreq: array of LongWord; const ofFreq: array of LongWord; const mlFreq: array of LongWord; ADictId: LongWord): TByteArray;

var
  ZstdPackLastError: Integer = 0;

implementation

const
  MAGIC_FRAME = $FD2FB528;
  MAGIC_DICT = $EC30A437;
  BLOCK_SRC = 128 * 1024;        // input consumed per block
  MAXLITS = BLOCK_SRC;

  LL_BASE: array[0..35] of LongWord = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536);
  LL_XTRA: array[0..35] of Byte = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16);
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

  // per-level effort: window log, chain depth, lazy, nice length
  LEVELS: array[1..9] of record
    w, t, n: Integer;
    lz: Boolean;
  end = (
    (w: 19; t: 4; n: 16; lz: false),
    (w: 20; t: 8; n: 24; lz: false),
    (w: 21; t: 16; n: 32; lz: false),
    (w: 21; t: 24; n: 48; lz: true),
    (w: 22; t: 32; n: 64; lz: true),
    (w: 22; t: 48; n: 96; lz: true),
    (w: 23; t: 64; n: 128; lz: true),
    (w: 24; t: 96; n: 192; lz: true),
    (w: 24; t: 128; n: 273; lz: true));

var
  llSmall: array[0..63] of Byte;     // literal length -> code, short range
  mlSmall: array[0..127] of Byte;    // (match length - 3) -> code
  // predefined-table bit cost per symbol, Q8 fixed point
  defCostLL: array[0..35] of LongWord;
  defCostML: array[0..52] of LongWord;
  defCostOF: array[0..28] of LongWord;
  tablesReady: Boolean = false;

function bitTop(v: LongWord): Integer; inline;
begin
  result := BsrDWord(v);
end;

function llCode(v: LongWord): Integer; inline;
begin
  if v < 64 then
    result := llSmall[v]
  else
    result := bitTop(v) + 19;
end;

function mlCode(mlBase: LongWord): Integer; inline;
begin
  if mlBase < 128 then
    result := mlSmall[mlBase]
  else
    result := bitTop(mlBase) + 36;
end;

procedure initTables;
  procedure costsOf(const def: array of SmallInt; accLog: Integer;
    var cost: array of LongWord);
  begin
    for var s := 0 to High(def) do begin
      var p: Integer := def[s];
      if p < 0 then p := 1;
      // bits = accLog - log2(p), in Q8
      cost[s] := Round((accLog - ln(p) / ln(2)) * 256);
    end;
  end;

begin
  if tablesReady then exit;
  for var c := 0 to 35 do
    for var v := LL_BASE[c] to LL_BASE[c] + (LongWord(1) shl LL_XTRA[c]) - 1 do begin
      if v > 63 then break;
      llSmall[v] := c;
    end;
  for var c := 0 to 52 do
    for var v := ML_BASE[c] - 3 to ML_BASE[c] - 3 + (LongWord(1) shl ML_XTRA[c]) - 1 do begin
      if v > 127 then break;
      mlSmall[v] := c;
    end;
  costsOf(DEF_LL, 6, defCostLL);
  costsOf(DEF_ML, 6, defCostML);
  costsOf(DEF_OF, 5, defCostOF);
  tablesReady := true;
end;

{ ---------------------------------------------------------------- }
{ forward bit writer; entropy streams end with a sentinel 1-bit     }
{ ---------------------------------------------------------------- }

type
  TForwBits = record
    dst: PByte;
    at: SizeInt;
    acc: QWord;
    cnt: Integer;
    procedure Open(adst: PByte; start: SizeInt);
    procedure Put(v: LongWord; n: Integer); inline;
    procedure Flush; inline;
    procedure Close;             // sentinel + zero pad to byte
  end;

procedure TForwBits.Open(adst: PByte; start: SizeInt);
begin
  dst := adst;
  at := start;
  acc := 0;
  cnt := 0;
end;

procedure TForwBits.Put(v: LongWord; n: Integer);
begin
  acc := acc or (QWord(v and ((QWord(1) shl n) - 1)) shl cnt);
  Inc(cnt, n);
  Flush;
end;

procedure TForwBits.Flush;
begin
  while cnt >= 8 do begin
    dst[at] := Byte(acc);
    Inc(at);
    acc := acc shr 8;
    Dec(cnt, 8);
  end;
end;

procedure TForwBits.Close;
begin
  Put(1, 1);
  if cnt > 0 then begin
    dst[at] := Byte(acc);
    Inc(at);
    acc := 0;
    cnt := 0;
  end;
end;

{ ---------------------------------------------------------------- }
{ FSE encoder: normalization, header serialization, coding table    }
{ ---------------------------------------------------------------- }

{ scale raw counts to a power-of-two total; -1 marks "less than 1" }
function fseNormalize(const count: array of LongWord; total: SizeInt; nSym, accLog: Integer; out norm: array of SmallInt): Boolean;
var
  size, left, lowT, big, bigSym: Integer;
  n: Integer;
begin
  result := false;
  size := 1 shl accLog;
  left := size;
  lowT := total shr accLog;
  big := -1;
  bigSym := -1;
  for var s := 0 to nSym - 1 do begin
    norm[s] := 0;
    if count[s] = 0 then continue;
    if Integer(count[s]) <= lowT then begin
      norm[s] := -1;
      Dec(left);
    end
    else begin
      n := (QWord(count[s]) * size) div QWord(total);
      if n = 0 then n := 1;
      norm[s] := n;
      Dec(left, n);
      if Integer(count[s]) > big then begin
        big := count[s];
        bigSym := s;
      end;
    end;
  end;
  if bigSym < 0 then exit;            // nothing above the low threshold
  if left > 0 then
    norm[bigSym] := norm[bigSym] + left
  else
    while left < 0 do begin
      // shave overflow off the heaviest entries, never below 1
      var pick: Integer := -1;
      for var s := 0 to nSym - 1 do
        if (norm[s] > 1) and ((pick < 0) or (norm[s] > norm[pick])) then
          pick := s;
      if pick < 0 then exit;
      norm[pick] := norm[pick] - 1;
      Inc(left);
    end;
  result := true;
end;

{ serialize the distribution; returns bytes written into dst[at..] }
function fseWriteSpec(const norm: array of SmallInt; nSym, accLog: Integer; dst: PByte; at: SizeInt): SizeInt;
var
  bw: TForwBits;
  remain, s, bits, small, val: Integer;
begin
  bw.Open(dst, at);
  bw.Put(accLog - 5, 4);
  remain := (1 shl accLog) + 1;
  s := 0;
  while remain > 1 do begin
    bits := bitTop(LongWord(remain)) + 1;
    small := (1 shl bits) - 1 - remain;
    val := norm[s] + 1;                       // 0 encodes "less than 1"
    if val < small then
      bw.Put(val, bits - 1)
    else if val < (1 shl (bits - 1)) then
      bw.Put(val, bits)
    else
      bw.Put(val + small, bits);
    if norm[s] > 0 then
      Dec(remain, norm[s])
    else if norm[s] < 0 then
      Dec(remain);                            // -1 weighs one point
    Inc(s);
    if (val = 1) and (remain > 1) then begin  // zero-prob run flags
      var run: Integer := 0;
      while (s + run < nSym) and (norm[s + run] = 0) do
        Inc(run);
      while true do begin
        if run >= 3 then begin
          bw.Put(3, 2);
          Inc(s, 3);
          Dec(run, 3);
        end
        else begin
          bw.Put(run, 2);
          Inc(s, run);
          break;
        end;
      end;
    end;
  end;
  // round up to whole bytes (no sentinel here, the spec reader counts)
  if bw.cnt > 0 then begin
    bw.dst[bw.at] := Byte(bw.acc);
    Inc(bw.at);
  end;
  result := bw.at - at;
end;

function fseBuildEnc(var e: TFseEnc; const norm: array of SmallInt; nSym, accLog: Integer): Boolean;
var
  size, hiCells, pos, step, mask, total: Integer;
  spread: array of Byte;
  cumul: array[0..256] of Integer;
  freq: Integer;
begin
  result := false;
  size := 1 shl accLog;
  e.accLog := accLog;
  SetLength(e.stateTab, size);
  SetLength(e.dBits, nSym);
  SetLength(e.dState, nSym);
  SetLength(spread, size);
  // mirror of the decoder's layout: low-prob symbols park at the top
  hiCells := 0;
  for var s := 0 to nSym - 1 do
    if norm[s] = -1 then begin
      Inc(hiCells);
      spread[size - hiCells] := s;
    end;
  step := (size shr 1) + (size shr 3) + 3;
  mask := size - 1;
  pos := 0;
  for var s := 0 to nSym - 1 do
    for var i := 1 to norm[s] do begin
      spread[pos] := s;
      repeat
        pos := (pos + step) and mask;
      until pos < size - hiCells;
    end;
  if pos <> 0 then exit;
  // rank -> state mapping
  cumul[0] := 0;
  for var s := 0 to nSym - 1 do begin
    freq := norm[s];
    if freq < 0 then freq := 1;
    cumul[s + 1] := cumul[s] + freq;
  end;
  for var u := 0 to size - 1 do begin
    var s: Integer := spread[u];
    e.stateTab[cumul[s]] := size + u;
    Inc(cumul[s]);
  end;
  // per-symbol transforms
  total := 0;
  for var s := 0 to nSym - 1 do begin
    case norm[s] of
      0: begin
        e.dBits[s] := ((accLog + 1) shl 16) - size;  // never used
        e.dState[s] := 0;
      end;
      -1, 1: begin
        e.dBits[s] := (accLog shl 16) - size;
        e.dState[s] := total - 1;
        Inc(total);
      end;
      else begin
        var mb: Integer := accLog - bitTop(norm[s] - 1);
        e.dBits[s] := (mb shl 16) - (norm[s] shl mb);
        e.dState[s] := total - norm[s];
        Inc(total, norm[s]);
      end;
    end;
  end;
  result := true;
end;

function fseEncInit(const e: TFseEnc; sym: Integer): Integer; inline;
var
  nb: Integer;
begin
  nb := (e.dBits[sym] + 32768) shr 16;
  result := e.stateTab[(((nb shl 16) - e.dBits[sym]) shr nb) + e.dState[sym]];
end;

procedure fseEncPush(const e: TFseEnc; var bw: TForwBits; var state: Integer; sym: Integer); inline;
var
  nb: Integer;
begin
  nb := (state + e.dBits[sym]) shr 16;
  bw.Put(state, nb);
  state := e.stateTab[(state shr nb) + e.dState[sym]];
end;

procedure fseEncFlush(const e: TFseEnc; var bw: TForwBits; state: Integer); inline;
begin
  bw.Put(state, e.accLog);
end;

{ entropy cost of a histogram under a normalized table, Q8 bits }
function fseCost(const count: array of LongWord; const norm: array of SmallInt; nSym, accLog: Integer): QWord;
begin
  result := 0;
  for var s := 0 to nSym - 1 do begin
    if count[s] = 0 then continue;
    if norm[s] = 0 then exit(High(QWord));   // not representable
    var p: Integer := norm[s];
    if p < 0 then p := 1;
    result := result +
      QWord(count[s]) * (LongWord(accLog * 256) - LongWord(bitTop(p) * 256));
    // fractional part of log2: linear approximation between powers of two
    var frac: LongWord := (QWord(p) shl 8) shr bitTop(p) - 256;
    result := result - QWord(count[s]) * frac * 184 shr 8;
  end;
end;

{ ---------------------------------------------------------------- }
{ length-limited huffman code lengths via package-merge             }
{ ---------------------------------------------------------------- }

const
  HUF_MAXBITS = 11;

{ counts -> code lengths (0 = absent), optimal under HUF_MAXBITS.
  Returns number of distinct present symbols. }
function hufLengths(const count: array of LongWord; nSym: Integer; out len: array of Byte): Integer;
type
  TItem = record
    w: QWord;
    sym: Integer;    // -1 = package
  end;
var
  leaves: array of TItem;
  cur, nxt: array of TItem;
  nLeaves: Integer;
  takeCount: array[1..HUF_MAXBITS] of Integer;
  lists: array[1..HUF_MAXBITS] of array of TItem;
begin
  nLeaves := 0;
  SetLength(leaves, nSym);
  for var s := 0 to nSym - 1 do begin
    len[s] := 0;
    if count[s] > 0 then begin
      leaves[nLeaves].w := count[s];
      leaves[nLeaves].sym := s;
      Inc(nLeaves);
    end;
  end;
  result := nLeaves;
  if nLeaves < 2 then begin
    if nLeaves = 1 then len[leaves[0].sym] := 1;
    exit;
  end;
  // sort leaves ascending by weight (stable on symbol)
  for var i := 1 to nLeaves - 1 do begin
    var t: TItem := leaves[i];
    var j: Integer := i - 1;
    while (j >= 0) and ((leaves[j].w > t.w) or
      ((leaves[j].w = t.w) and (leaves[j].sym > t.sym))) do begin
      leaves[j + 1] := leaves[j];
      Dec(j);
    end;
    leaves[j + 1] := t;
  end;
  // build the package lists from the deepest level up
  cur := Copy(leaves);
  lists[HUF_MAXBITS] := cur;
  for var lvl := HUF_MAXBITS - 1 downto 1 do begin
    // package pairs of cur, then merge with the fresh leaves
    var nPk: Integer := Length(cur) div 2;
    nxt := nil;
    SetLength(nxt, nLeaves + nPk);
    var li: Integer := 0;
    var pi: Integer := 0;
    var k: Integer := 0;
    while (li < nLeaves) or (pi < nPk) do begin
      var pw: QWord := 0;
      if pi < nPk then pw := cur[2 * pi].w + cur[2 * pi + 1].w;
      if (pi >= nPk) or ((li < nLeaves) and (leaves[li].w <= pw)) then begin
        nxt[k] := leaves[li];
        Inc(li);
      end
      else begin
        nxt[k].w := pw;
        nxt[k].sym := -1;
        Inc(pi);
      end;
      Inc(k);
    end;
    lists[lvl] := nxt;
    cur := nxt;
  end;
  // walk back down: level 1 contributes 2(n-1) items, every package
  // taken pulls two items of the level below
  takeCount[1] := 2 * (nLeaves - 1);
  for var lvl := 1 to HUF_MAXBITS do begin
    var pk: Integer := 0;
    var n: Integer := takeCount[lvl];
    if n > Length(lists[lvl]) then n := Length(lists[lvl]);
    for var i := 0 to n - 1 do
      if lists[lvl][i].sym < 0 then
        Inc(pk)
      else
        Inc(len[lists[lvl][i].sym]);
    if lvl < HUF_MAXBITS then
      takeCount[lvl + 1] := 2 * pk;
  end;
end;

{ ---------------------------------------------------------------- }
{ canonical huffman codes and the weights description writer        }
{ ---------------------------------------------------------------- }

{ code lengths -> canonical code values, the same ordering the
  decoder reconstructs: ascending weight, natural symbol order }
procedure hufCanonCodes(const hlen: array of Byte; lastSym, maxBits: Integer; var code: array of Word);
var
  cur: Integer;
begin
  cur := 0;
  for var w := 1 to maxBits do
    for var s := 0 to lastSym do begin
      if (hlen[s] = 0) or (maxBits + 1 - hlen[s] <> w) then continue;
      code[s] := cur shr (w - 1);
      Inc(cur, 1 shl (w - 1));
    end;
end;

{ serialize huffman weights (the final weight is implied); nW is the
  count of written weights; returns bytes or 0 when not encodable }
function hufWriteDesc(const weights: array of Byte; nW: Integer; dst: PByte): SizeInt;
var
  wCount: array[0..15] of LongWord;
  wNorm: array[0..15] of SmallInt;
  enc: TFseEnc;
  bw: TForwBits;
  accLog, maxW, distinctW: Integer;
  directLen, s1, s2, i: Integer;
  fseBody: array[0..511] of Byte;
  descLen: SizeInt;
begin
  result := 0;
  for var w := 0 to 15 do wCount[w] := 0;
  maxW := 0;
  for i := 0 to nW - 1 do begin
    Inc(wCount[weights[i]]);
    if weights[i] > maxW then maxW := weights[i];
  end;
  directLen := 1 + (nW + 1) div 2;
  // fse-compressed weights, two interleaved states
  if nW >= 2 then begin
    distinctW := 0;
    for var w := 0 to maxW do
      if wCount[w] > 0 then Inc(distinctW);
    accLog := 6;
    while (1 shl (accLog - 1)) > nW do Dec(accLog);
    if accLog < 5 then accLog := 5;
    if (distinctW >= 2) and
      fseNormalize(wCount, nW, maxW + 1, accLog, wNorm) then begin
      descLen := fseWriteSpec(wNorm, maxW + 1, accLog, @fseBody[0], 0);
      if fseBuildEnc(enc, wNorm, maxW + 1, accLog) then begin
        bw.Open(@fseBody[0], descLen);
        if odd(nW) then begin
          s1 := fseEncInit(enc, weights[nW - 1]);
          s2 := fseEncInit(enc, weights[nW - 2]);
        end
        else begin
          s2 := fseEncInit(enc, weights[nW - 1]);
          s1 := fseEncInit(enc, weights[nW - 2]);
        end;
        for i := nW - 3 downto 0 do
          if odd(i) then
            fseEncPush(enc, bw, s2, weights[i])
          else
            fseEncPush(enc, bw, s1, weights[i]);
        fseEncFlush(enc, bw, s2);
        fseEncFlush(enc, bw, s1);
        bw.Close;
        if (bw.at <= 127) and (1 + bw.at < directLen) then begin
          dst[0] := Byte(bw.at);
          Move(fseBody[0], dst[1], bw.at);
          exit(1 + bw.at);
        end;
      end;
    end;
  end;
  // direct nibbles; only fits while every symbol stays below 128
  if nW > 128 then exit;
  dst[0] := Byte(127 + nW);
  for i := 0 to (nW + 1) div 2 - 1 do dst[1 + i] := 0;
  for i := 0 to nW - 1 do
    if odd(i) then
      dst[1 + i div 2] := dst[1 + i div 2] or weights[i]
    else
      dst[1 + i div 2] := weights[i] shl 4;
  result := 1 + (nW + 1) div 2;
end;

{ ---------------------------------------------------------------- }
{ decode-side helpers, needed to load structured dictionaries       }
{ ---------------------------------------------------------------- }

type
  TFseDecCell = packed record
    sym: Byte;
    bits: Byte;
    base: Word;
  end;

  { forward bit reader over fse table descriptions }
  TFwdBits = record
    p: PByte;
    len, bytePos: SizeInt;
    acc: QWord;
    cnt: Integer;
    procedure Open(data: PByte; alen: SizeInt);
    function Peek(n: Integer): LongWord;
    procedure Drop(n: Integer);
    function Take(n: Integer): LongWord;
    function BytesUsed: SizeInt;
    function Overran: Boolean;
  end;

  { backward reader for the fse-compressed huffman weights }
  TBackBits = record
    p: PByte;
    bytesBelow: SizeInt;
    acc: QWord;
    cnt: Integer;
    bad: Boolean;
    procedure Open(data: PByte; alen: SizeInt);
    function BitsLeft: SizeInt;
    function TakePad(n: Integer): LongWord;
  end;

procedure TFwdBits.Open(data: PByte; alen: SizeInt);
begin
  p := data;
  len := alen;
  bytePos := 0;
  acc := 0;
  cnt := 0;
end;

function TFwdBits.Peek(n: Integer): LongWord;
begin
  while (cnt < n) and (bytePos < len) do begin
    acc := acc or (QWord(p[bytePos]) shl cnt);
    Inc(bytePos);
    Inc(cnt, 8);
  end;
  result := acc and ((QWord(1) shl n) - 1);
end;

procedure TFwdBits.Drop(n: Integer);
begin
  acc := acc shr n;
  Dec(cnt, n);
end;

function TFwdBits.Take(n: Integer): LongWord;
begin
  result := Peek(n);
  Drop(n);
end;

function TFwdBits.BytesUsed: SizeInt;
begin
  result := (bytePos * 8 - cnt + 7) div 8;
end;

function TFwdBits.Overran: Boolean;
begin
  result := bytePos * 8 - cnt > len * 8;
end;

procedure TBackBits.Open(data: PByte; alen: SizeInt);
var
  last: Byte;
begin
  p := data;
  acc := 0;
  cnt := 0;
  bytesBelow := 0;
  bad := (alen <= 0);
  if bad then exit;
  last := data[alen - 1];
  if last = 0 then begin
    bad := true;
    exit;
  end;
  cnt := bitTop(last);
  acc := last and ((1 shl cnt) - 1);
  bytesBelow := alen - 1;
end;

function TBackBits.BitsLeft: SizeInt;
begin
  result := bytesBelow * 8 + cnt;
end;

function TBackBits.TakePad(n: Integer): LongWord;
begin
  if n = 0 then exit(0);
  while (cnt < n) and (bytesBelow > 0) do begin
    Dec(bytesBelow);
    acc := (acc shl 8) or p[bytesBelow];
    Inc(cnt, 8);
  end;
  if cnt >= n then begin
    result := (acc shr (cnt - n)) and ((QWord(1) shl n) - 1);
    Dec(cnt, n);
    acc := acc and ((QWord(1) shl cnt) - 1);
  end
  else begin
    result := (acc shl (n - cnt)) and ((QWord(1) shl n) - 1);
    cnt := 0;
    acc := 0;
  end;
end;

{ parse a serialized fse distribution (mirror of the decoder) }
function fseReadCounts(p: PByte; len: SizeInt; maxAcc, maxSym: Integer; out norm: array of SmallInt; out accLog: Integer; out used: SizeInt): Boolean;
var
  rd: TFwdBits;
  remain, sym, bits, small, v, val, rep: Integer;
begin
  result := false;
  used := 0;
  accLog := 0;
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
    val := val - 1;
    if val >= 0 then begin
      norm[sym] := val;
      Dec(remain, val);
      Inc(sym);
      if val = 0 then
        repeat
          rep := Integer(rd.Take(2));
          for var i := 1 to rep do begin
            if sym > maxSym then exit;
            norm[sym] := 0;
            Inc(sym);
          end;
        until rep <> 3;
    end
    else begin
      norm[sym] := -1;
      Dec(remain);
      Inc(sym);
    end;
  end;
  if (remain <> 1) or rd.Overran then exit;
  // a legal distribution carries at least two present symbols
  begin
    var present: Integer := 0;
    for var i := 0 to maxSym do
      if norm[i] <> 0 then Inc(present);
    if present < 2 then exit;
  end;
  used := rd.BytesUsed;
  result := true;
end;

{ normalized counts -> decoding table (mirror of the decoder) }
function fseBuildDec(var cells: array of TFseDecCell; const norm: array of SmallInt; nSym, accLog: Integer): Boolean;
var
  size, mask, step, pos, hiCells, present, nxt: Integer;
  counter: array[0..255] of Word;
begin
  result := false;
  size := 1 shl accLog;
  if size > Length(cells) then exit;
  hiCells := 0;
  present := 0;
  for var s := 0 to nSym - 1 do begin
    if norm[s] <> 0 then Inc(present);
    if norm[s] = -1 then begin
      Inc(hiCells);
      cells[size - hiCells].sym := s;
      counter[s] := 1;
    end
    else
      counter[s] := norm[s];
  end;
  if present < 2 then exit;
  step := (size shr 1) + (size shr 3) + 3;
  mask := size - 1;
  pos := 0;
  for var s := 0 to nSym - 1 do
    for var i := 1 to norm[s] do begin
      cells[pos].sym := s;
      repeat
        pos := (pos + step) and mask;
      until pos < size - hiCells;
    end;
  if pos <> 0 then exit;
  for var u := 0 to size - 1 do begin
    nxt := counter[cells[u].sym];
    Inc(counter[cells[u].sym]);
    cells[u].bits := accLog - bitTop(nxt);
    cells[u].base := (nxt shl cells[u].bits) - size;
  end;
  result := true;
end;

{ huffman tree description -> code lengths (mirror of the decoder,
  except it keeps lengths instead of a lookup table) }
function hufReadDesc(p: PByte; len: SizeInt; out used: SizeInt; out hlen: array of Byte; out maxBits: Integer): Boolean;
var
  weights: array[0..255] of Byte;
  norm: array[0..15] of SmallInt;
  cells: array[0..63] of TFseDecCell;
  nw, accLog, lastW: Integer;
  descLen, fseLen: SizeInt;
  rd: TBackBits;
  s1, s2: Integer;
  sum, p2, rest: LongWord;
begin
  result := false;
  used := 0;
  maxBits := 0;
  for var i := 0 to 255 do
    hlen[i] := 0;
  if len < 1 then exit;
  nw := 0;
  if p^ >= 128 then begin
    nw := p^ - 127;
    if 1 + (nw + 1) div 2 > len then exit;
    for var i := 0 to nw - 1 do
      if (i and 1) = 0 then
        weights[i] := p[1 + i div 2] shr 4
      else
        weights[i] := p[1 + i div 2] and 15;
    used := 1 + (nw + 1) div 2;
  end
  else begin
    fseLen := p^;
    if 1 + fseLen > len then exit;
    if not fseReadCounts(p + 1, fseLen, 6, 15, norm, accLog, descLen) then
      exit;
    if not fseBuildDec(cells, norm, 16, accLog) then exit;
    rd.Open(p + 1 + descLen, fseLen - descLen);
    if rd.bad then exit;
    if rd.BitsLeft < 2 * accLog then exit;
    s1 := Integer(rd.TakePad(accLog));
    s2 := Integer(rd.TakePad(accLog));
    while true do begin
      if nw > 254 then exit;
      weights[nw] := cells[s1].sym;
      Inc(nw);
      if rd.BitsLeft < cells[s1].bits then begin
        if nw > 254 then exit;
        weights[nw] := cells[s2].sym;
        Inc(nw);
        break;
      end;
      s1 := cells[s1].base + Integer(rd.TakePad(cells[s1].bits));
      if nw > 254 then exit;
      weights[nw] := cells[s2].sym;
      Inc(nw);
      if rd.BitsLeft < cells[s2].bits then begin
        if nw > 254 then exit;
        weights[nw] := cells[s1].sym;
        Inc(nw);
        break;
      end;
      s2 := cells[s2].base + Integer(rd.TakePad(cells[s2].bits));
    end;
    used := 1 + fseLen;
  end;
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
  if (rest and (rest - 1)) <> 0 then exit;
  lastW := bitTop(rest) + 1;
  if (maxBits > 11) or (nw >= 256) then exit;
  weights[nw] := lastW;
  Inc(nw);
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
  for var i := 0 to nw - 1 do
    if weights[i] > 0 then
      hlen[i] := maxBits + 1 - weights[i];
  result := true;
end;

{ ---------------------------------------------------------------- }
{ xxhash64 (streaming)                                              }
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

procedure TZstdEncoder.xxReset;
begin
  xxV[0] := QWord($60EA27EEADC0B5D6);   // XXP1 + XXP2 (mod 2^64)
  xxV[1] := XXP2;
  xxV[2] := 0;
  xxV[3] := QWord($61C8864E7A143579);   // 0 - XXP1   (mod 2^64)
  xxCnt := 0;
  xxTotal := 0;
end;

procedure TZstdEncoder.xxFeed(p: PByte; len: SizeInt);
var
  take: SizeInt;
begin
  if not withSum then exit;
  Inc(xxTotal, len);
  while len > 0 do begin
    if (xxCnt = 0) and (len >= 32) then begin
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

function TZstdEncoder.xxDigest: QWord;
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
{ TZstdEncoder plumbing                                             }
{ ---------------------------------------------------------------- }

procedure TZstdEncoder.Init(ALevel: Integer; AChecksum: Boolean);
begin
  initTables;
  if ALevel < 1 then ALevel := 1;
  if ALevel > 9 then ALevel := 9;
  level := ALevel;
  withSum := AChecksum;
  wlog := LEVELS[level].w;
  tries := LEVELS[level].t;
  niceLen := LEVELS[level].n;
  doLazy := LEVELS[level].lz;
  buf := nil;
  buflen := 0;
  err := 0;
  totalbytes := 0;
  progCb := nil;
  lastPct := -1;
  started := false;
  done := false;
  consumed := 0;
  win := nil;
  winLen := 0;
  procPos := 0;
  insPos := 0;
  seqCnt := 0;
  litCnt := 0;
  dictId := 0;
  dictPrefix := 0;
  framePosBase := 0;
  dictHasEntropy := false;
  dictReps[0] := 1;
  dictReps[1] := 4;
  dictReps[2] := 8;
  statsOn := false;
  statSeqs := 0;
  FillChar(statLit, SizeOf(statLit), 0);
  FillChar(statLL, SizeOf(statLL), 0);
  FillChar(statOF, SizeOf(statOF), 0);
  FillChar(statML, SizeOf(statML), 0);
  xxReset;
end;

procedure TZstdEncoder.UseDictionary(Data: Pointer; Len: SizeInt);
var
  p: PByte;
  at, used: SizeInt;
  csize: SizeInt;
  maxBits: Integer;
begin
  if done or started or (consumed > 0) or (dictPrefix > 0) then begin
    err := 1;
    exit;
  end;
  p := Data;
  if Len < 8 then begin
    err := 1;
    exit;
  end;
  at := 0;
  if PLongWord(p)^ = MAGIC_DICT then begin
    dictId := PLongWord(p + 4)^;
    if dictId = 0 then begin
      err := 1;
      exit;
    end;
    at := 8;
    if not hufReadDesc(p + at, Len - at, used, dictHufLen, maxBits)
    then begin
      err := 1;
      exit;
    end;
    hufCanonCodes(dictHufLen, 255, maxBits, dictHufCode);
    Inc(at, used);
    // offsets, match lengths, literal lengths order; channel ids 1/2/0
    if not fseReadCounts(p + at, Len - at, 8, 31, dictNorm[1], dictAcc[1],
      used) then begin
      err := 1;
      exit;
    end;
    Inc(at, used);
    if not fseReadCounts(p + at, Len - at, 9, 52, dictNorm[2], dictAcc[2],
      used) then begin
      err := 1;
      exit;
    end;
    Inc(at, used);
    if not fseReadCounts(p + at, Len - at, 9, 35, dictNorm[0], dictAcc[0],
      used) then begin
      err := 1;
      exit;
    end;
    Inc(at, used);
    if Len - at < 12 then begin
      err := 1;
      exit;
    end;
    csize := Len - at - 12;
    for var i := 0 to 2 do begin
      dictReps[i] := PLongWord(p + at)^;
      Inc(at, 4);
      if (dictReps[i] = 0) or (dictReps[i] > csize) then begin
        err := 1;
        exit;
      end;
    end;
    dictHasEntropy := true;
  end;
  // the content (or the whole raw blob) becomes the window prefix
  csize := Len - at;
  if csize > 0 then begin
    if winLen + csize > Length(win) then
      SetLength(win, csize + 1024 * 1024);
    Move(p[at], win[0], csize);
    winLen := csize;
    procPos := csize;
    insPos := 0;
    dictPrefix := csize;
    framePosBase := -csize;
  end;
end;

procedure TZstdEncoder.UseDictionary(const Data: array of Byte);
begin
  if Length(Data) > 0 then
    UseDictionary(@Data[0], Length(Data))
  else
    err := 1;
end;

procedure TZstdEncoder.onProgress(ACallback: TZstdProgressProc);
begin
  progCb := ACallback;
end;

procedure TZstdEncoder.report;
var
  pct: Integer;
begin
  if (progCb = nil) or (totalbytes = 0) then exit;
  if consumed >= totalbytes then
    pct := 100
  else
    pct := Integer((consumed * 100) div totalbytes);
  if pct <> lastPct then begin
    lastPct := pct;
    progCb(pct);
  end;
end;

procedure TZstdEncoder.ResetBuf;
begin
  buflen := 0;
end;

procedure TZstdEncoder.emit(const src; n: SizeInt);
begin
  if buflen + n > Length(buf) then begin
    var want: SizeInt := buflen + n;
    if want < 2 * Length(buf) then want := 2 * Length(buf);
    if want < 64 * 1024 then want := 64 * 1024;
    SetLength(buf, want);
  end;
  Move(src, buf[buflen], n);
  Inc(buflen, n);
end;

procedure TZstdEncoder.emitByte(b: Byte);
begin
  emit(b, 1);
end;

{ write magic + frame header; sizes the window and match structures }
procedure TZstdEncoder.startFrame(knownSize: Boolean; size: QWord);
var
  hd: array[0..13] of Byte;
  n: Integer;
  fhd: Byte;
  single: Boolean;
  fcsFlag: Integer;
  effLog: Integer;
begin
  PLongWord(@hd[0])^ := MAGIC_FRAME;
  n := 4;
  single := knownSize and (size <= 8 * 1024 * 1024);
  if single then begin
    // window equals content size; trim the match window to fit
    winSize := SizeInt(size);
    if winSize < 1 then winSize := 1;
    effLog := bitTop(LongWord(winSize)) + 1;
    if (SizeInt(1) shl (effLog - 1)) = winSize then Dec(effLog);
    if effLog > wlog then effLog := wlog; // never matters: size <= 8M
  end
  else begin
    effLog := wlog;
    if knownSize then
      while (effLog > 10) and ((QWord(1) shl (effLog - 1)) >= size) do
        Dec(effLog);
    winSize := SizeInt(1) shl effLog;
  end;
  if knownSize then begin
    if single then begin
      if size < 256 then fcsFlag := 0
      else if size <= 65791 then fcsFlag := 1
      else fcsFlag := 2;
    end
    else if size <= 65791 then begin
      if size >= 256 then fcsFlag := 1 else fcsFlag := 2;
    end
    else if size < QWord(1) shl 32 then fcsFlag := 2
    else fcsFlag := 3;
  end
  else
    fcsFlag := 0;
  fhd := fcsFlag shl 6;
  if single then fhd := fhd or $20;
  if withSum then fhd := fhd or $04;
  // dictionary id field, sized to the value
  var didSize: Integer := 0;
  if dictId <> 0 then begin
    if dictId <= 255 then begin
      didSize := 1;
      fhd := fhd or 1;
    end
    else if dictId <= 65535 then begin
      didSize := 2;
      fhd := fhd or 2;
    end
    else begin
      didSize := 4;
      fhd := fhd or 3;
    end;
  end;
  hd[n] := fhd;
  Inc(n);
  if not single then begin
    hd[n] := (effLog - 10) shl 3;     // exponent only, mantissa 0
    Inc(n);
  end;
  for var i := 0 to didSize - 1 do begin
    hd[n] := Byte(dictId shr (8 * i));
    Inc(n);
  end;
  case fcsFlag of
    0: if single then begin
      hd[n] := Byte(size);
      Inc(n);
    end;
    1: begin
      var v: Word := Word(size - 256);
      hd[n] := Byte(v);
      hd[n + 1] := Byte(v shr 8);
      Inc(n, 2);
    end;
    2: begin
      PLongWord(@hd[n])^ := LongWord(size);
      Inc(n, 4);
    end;
    3: begin
      PQWord(@hd[n])^ := size;
      Inc(n, 8);
    end;
  end;
  emit(hd[0], n);
  blockCap := winSize;
  if blockCap > BLOCK_SRC then blockCap := BLOCK_SRC;
  // match finder structures
  hbits := effLog - 2;
  if hbits < 13 then hbits := 13;
  if hbits > 18 then hbits := 18;
  SetLength(head, SizeInt(1) shl hbits);
  for var i := 0 to High(head) do head[i] := -1;
  SetLength(head3, 1 shl 14);
  for var i := 0 to High(head3) do head3[i] := -1;
  chainMask := (SizeInt(1) shl (effLog + 1)) - 1;
  if chainMask < 4 * BLOCK_SRC - 1 then chainMask := 4 * BLOCK_SRC - 1;
  SetLength(chain, chainMask + 1);
  insPos := 0;
  reps[0] := dictReps[0];
  reps[1] := dictReps[1];
  reps[2] := dictReps[2];
  pHufLive := false;
  pSeqKind[0] := 0;
  pSeqKind[1] := 0;
  pSeqKind[2] := 0;
  if dictHasEntropy then begin
    // the dictionary tables are the decoder's starting state, so the
    // first block may already code treeless literals and repeat tables
    Move(dictHufLen[0], pHufLen[0], SizeOf(pHufLen));
    Move(dictHufCode[0], pHufCode[0], SizeOf(pHufCode));
    pHufLive := true;
    for var ch := 0 to 2 do begin
      var nSym: Integer;
      case ch of
        0: nSym := 36;
        1: nSym := 32;
        else nSym := 53;
      end;
      if fseBuildEnc(pSeqEnc[ch], dictNorm[ch], nSym, dictAcc[ch]) then begin
        for var s := 0 to 63 do
          pSeqNorm[ch][s] := dictNorm[ch][s];
        pSeqAcc[ch] := dictAcc[ch];
        pSeqKind[ch] := 1;
      end;
    end;
  end;
  SetLength(litBuf, MAXLITS + 8);
  SetLength(seqLL, BLOCK_SRC div 3 + 16);
  SetLength(seqML, BLOCK_SRC div 3 + 16);
  SetLength(seqOV, BLOCK_SRC div 3 + 16);
  SetLength(scratch, 8 * BLOCK_SRC);   // sequences can outgrow the source
  SetLength(litSec, MAXLITS + 4096);
  started := true;
end;

{ drop everything older than the window, rebase all indexes }
procedure TZstdEncoder.slideWindow;
var
  delta: SizeInt;
begin
  if procPos <= winSize + 6 * BLOCK_SRC then exit;
  delta := procPos - winSize;
  Move(win[delta], win[0], winLen - delta);
  Dec(winLen, delta);
  Dec(procPos, delta);
  Dec(insPos, delta);
  Inc(framePosBase, delta);
  if insPos < 0 then insPos := 0;
  for var i := 0 to High(head) do
    if head[i] >= delta then Dec(head[i], delta) else head[i] := -1;
  for var i := 0 to High(head3) do
    if head3[i] >= delta then Dec(head3[i], delta) else head3[i] := -1;
  for var i := 0 to chainMask do
    if chain[i] >= delta then Dec(chain[i], delta) else chain[i] := -1;
end;

// multiplicative hashing wraps mod 2^32 by design; the QWord product
// is exact, the mask provides the wrap without tripping overflow checks
function hash4(p: PByte; bits: Integer): LongWord; inline;
begin
  result := LongWord((QWord(PLongWord(p)^) * 2654435761) and $FFFFFFFF)
    shr (32 - bits);
end;

function hash3(p: PByte): LongWord; inline;
begin
  result := LongWord((QWord(LongWord(p[0]) or (LongWord(p[1]) shl 8) or
    (LongWord(p[2]) shl 16)) * 506832829) and $FFFFFFFF) shr (32 - 14);
end;

{ index window positions [insPos, limit) }
procedure TZstdEncoder.indexUpTo(limit: SizeInt);
begin
  if limit > winLen - 3 then limit := winLen - 3;
  while insPos < limit do begin
    if insPos + 4 <= winLen then begin
      var h: LongWord := hash4(@win[insPos], hbits);
      chain[insPos and chainMask] := head[h];
      head[h] := insPos;
    end;
    head3[hash3(@win[insPos])] := insPos;
    Inc(insPos);
  end;
end;

{ note: keep classic var declarations in inline-marked routines; an
  unleashed block-scoped var inside an expanded inline body can land on
  the caller's frame and clobber its locals }
{ furthest allowed match distance at window position p: the window,
  except that the dictionary prefix stays reachable until the frame
  output walks past one full window }
function TZstdEncoder.maxDistAt(p: SizeInt): SizeInt;
begin
  if p + framePosBase <= winSize then
    result := p
  else
    result := winSize;
end;

function matchLen(a, b: PByte; cap: SizeInt): SizeInt; inline;
var
  n: SizeInt;
  x: QWord;
begin
  n := 0;
  while (n + 8 <= cap) and (PQWord(a + n)^ = PQWord(b + n)^) do
    Inc(n, 8);
  if (n < cap) and (n + 8 <= cap) then begin
    x := PQWord(a + n)^ xor PQWord(b + n)^;
    Inc(n, BsfQWord(x) shr 3);
    exit(n);
  end;
  while (n < cap) and (a[n] = b[n]) do
    Inc(n);
  result := n;
end;

{ best chain match at p; length 0 = nothing usable }
function TZstdEncoder.bestMatch(p, srcEnd: SizeInt; out dist: SizeInt): Integer;
var
  cap, q, d, l: SizeInt;
  budget: Integer;
  h: LongWord;
begin
  result := 0;
  dist := 0;
  cap := srcEnd - p;
  if cap < 4 then begin
    if cap < 3 then exit;
  end;
  // short match via the 3-byte slot, close range only
  if cap >= 3 then begin
    q := head3[hash3(@win[p])];
    if (q >= 0) and (q < p) then begin
      d := p - q;
      if (d <= 4096) and (win[q] = win[p]) and (win[q + 1] = win[p + 1]) and
        (win[q + 2] = win[p + 2]) then begin
        l := matchLen(@win[q], @win[p], cap);
        if l >= 3 then begin
          result := l;
          dist := d;
        end;
      end;
    end;
  end;
  if cap < 4 then exit;
  h := hash4(@win[p], hbits);
  q := head[h];
  budget := tries;
  var maxD: SizeInt := maxDistAt(p);
  while (q >= 0) and (budget > 0) and (result < cap) do begin
    d := p - q;
    if d > maxD then break;
    if (d > 0) and (win[q + result] = win[p + result]) then begin
      l := matchLen(@win[q], @win[p], cap);
      if (l > result) and ((l >= 4) or (d <= 4096)) then begin
        result := l;
        dist := d;
        if l >= niceLen then break;
      end;
    end;
    q := chain[q and chainMask];
    Dec(budget);
  end;
  if result < 3 then begin
    result := 0;
    dist := 0;
  end;
end;

{ longest repeat-offset match at p; ri = which rep won }
function TZstdEncoder.bestRep(p, srcEnd: SizeInt; out ri: Integer): Integer;
var
  cap, d, l: SizeInt;
begin
  result := 0;
  ri := -1;
  cap := srcEnd - p;
  if cap < 3 then exit;
  var maxD: SizeInt := maxDistAt(p);
  for var r := 0 to 2 do begin
    d := reps[r];
    if (d <= 0) or (d > maxD) then continue;
    if win[p - d] <> win[p] then continue;
    l := matchLen(@win[p - d], @win[p], cap);
    if l >= 3 then
      if (l > result + Ord(r > 0)) then begin   // newer reps cost less
        result := l;
        ri := r;
      end;
  end;
  if ri < 0 then result := 0;
end;

procedure TZstdEncoder.pushSeq(ll, ml, ofv: LongWord);
begin
  seqLL[seqCnt] := ll;
  seqML[seqCnt] := ml;
  seqOV[seqCnt] := ofv;
  Inc(seqCnt);
end;

{ turn win[procPos..srcEnd) into literals + sequences }
procedure TZstdEncoder.parseBlock(srcEnd: SizeInt);
var
  p, anchor: SizeInt;
  mLen, rLen, dist: SizeInt;
  ri: Integer;
  useRep: Boolean;
  ofv: LongWord;
  d2: SizeInt;
  r2: Integer;

  procedure takeLiteralRun(upTo: SizeInt);
  begin
    if upTo > anchor then begin
      Move(win[anchor], litBuf[litCnt], upTo - anchor);
      Inc(litCnt, upTo - anchor);
    end;
  end;

begin
  p := procPos;
  anchor := procPos;
  indexUpTo(p);
  while p < srcEnd do begin
    rLen := bestRep(p, srcEnd, ri);
    mLen := bestMatch(p, srcEnd, dist);
    if (rLen < 3) and (mLen < 3) then begin
      Inc(p);
      if p > insPos then indexUpTo(p);
      continue;
    end;
    // pick by gain: repeat codes cost almost no offset bits
    var curGain: SizeInt := -1000;
    if mLen >= 3 then curGain := 4 * mLen - bitTop(LongWord(dist) + 3);
    useRep := false;
    if rLen >= 3 then begin
      var rg: SizeInt := 4 * rLen - bitTop(LongWord(ri) + 2) + 1;
      if rg >= curGain then begin
        useRep := true;
        curGain := rg;
      end;
    end;
    // one-step lazy: deferring costs a literal, demand a real win
    if doLazy and (p + 1 < srcEnd) then begin
      var curLen: SizeInt;
      if useRep then curLen := rLen else curLen := mLen;
      if curLen < niceLen then begin
        indexUpTo(p + 1);
        var rl2: SizeInt := bestRep(p + 1, srcEnd, r2);
        var ml2: SizeInt := bestMatch(p + 1, srcEnd, d2);
        var g2: SizeInt := -1000;
        if ml2 >= 3 then g2 := 4 * ml2 - bitTop(LongWord(d2) + 3);
        if rl2 >= 3 then begin
          var rg2: SizeInt := 4 * rl2 - bitTop(LongWord(r2) + 2) + 1;
          if rg2 > g2 then g2 := rg2;
        end;
        if g2 > curGain + 4 then begin
          Inc(p);          // current byte becomes a literal, retry there
          continue;
        end;
      end;
    end;
    takeLiteralRun(p);
    var litLen: SizeInt := p - anchor;
    // pick the offset_value and update the recent offsets exactly the
    // way the decoder will replay them
    if useRep then begin
      dist := reps[ri];
      mLen := rLen;
      if (litLen = 0) and (ri = 0) then begin
        // rep0 without literals has no repeat code: send the plain form
        ofv := LongWord(dist) + 3;
        reps[2] := reps[1];
        reps[1] := reps[0];
        reps[0] := dist;
      end
      else begin
        if litLen = 0 then
          ofv := LongWord(ri)        // shifted code space: value ri means rep[ri]
        else
          ofv := LongWord(ri) + 1;
        if ri = 2 then reps[2] := reps[1];
        if ri >= 1 then begin
          reps[1] := reps[0];
          reps[0] := dist;
        end;
      end;
    end
    else begin
      ofv := LongWord(dist) + 3;
      reps[2] := reps[1];
      reps[1] := reps[0];
      reps[0] := dist;
    end;
    pushSeq(litLen, mLen, ofv);
    Inc(p, mLen);
    anchor := p;
    indexUpTo(p);
  end;
  takeLiteralRun(srcEnd);
  procPos := srcEnd;
end;

{ literals section into litSec; returns its size }
function TZstdEncoder.buildLiterals: SizeInt;
var
  count: array[0..255] of LongWord;
  hlen: array[0..255] of Byte;
  code: array[0..255] of Word;
  weights: array[0..255] of Byte;
  distinct, maxBits, lastSym: Integer;
  treeDesc: array[0..400] of Byte;
  treeLen: SizeInt;
  streams: TByteArray;

  procedure rawSection;
  var
    hdr: Integer;
  begin
    // raw literals, sized header
    if litCnt < 32 then begin
      litSec[0] := Byte(litCnt shl 3);   // type 0, size_format 0
      hdr := 1;
    end
    else if litCnt < 4096 then begin
      litSec[0] := Byte((litCnt shl 4) or $04);  // size_format 01
      litSec[1] := Byte(litCnt shr 4);
      hdr := 2;
    end
    else begin
      litSec[0] := Byte((litCnt shl 4) or $0C);  // size_format 11
      litSec[1] := Byte(litCnt shr 4);
      litSec[2] := Byte(litCnt shr 12);
      hdr := 3;
    end;
    if litCnt > 0 then
      Move(litBuf[0], litSec[hdr], litCnt);
    result := hdr + litCnt;
  end;

  procedure rleSection;
  begin
    if litCnt < 32 then begin
      litSec[0] := Byte((litCnt shl 3) or 1);
      litSec[1] := litBuf[0];
      result := 2;
    end
    else if litCnt < 4096 then begin
      litSec[0] := Byte((litCnt shl 4) or $04 or 1);
      litSec[1] := Byte(litCnt shr 4);
      litSec[2] := litBuf[0];
      result := 3;
    end
    else begin
      litSec[0] := Byte((litCnt shl 4) or $0C or 1);
      litSec[1] := Byte(litCnt shr 4);
      litSec[2] := Byte(litCnt shr 12);
      litSec[3] := litBuf[0];
      result := 4;
    end;
  end;

  { encode one huffman stream backwards-readable; returns bytes }
  function putStream(srcAt, n: SizeInt; dst: PByte; at: SizeInt): SizeInt;
  var
    bw: TForwBits;
  begin
    bw.Open(dst, at);
    for var i := srcAt + n - 1 downto srcAt do
      bw.Put(code[litBuf[i]], hlen[litBuf[i]]);
    bw.Close;
    result := bw.at - at;
  end;

  { weights -> tree description (direct or fse), into treeDesc }
  function buildTreeDesc: Boolean;
  begin
    treeLen := hufWriteDesc(weights, lastSym, @treeDesc[0]);
    result := treeLen > 0;
  end;

var
  totalStreams, per, lastN: SizeInt;
  s1n, s2n, s3n, s4n: SizeInt;
  comp, hdr: SizeInt;
  fourStreams: Boolean;
  v: QWord;
  litType: Integer;
begin
  result := 0;
  if litCnt = 0 then begin
    litSec[0] := 0;                     // raw, size 0
    exit(1);
  end;
  FillChar(count, SizeOf(count), 0);
  for var i := 0 to litCnt - 1 do
    Inc(count[litBuf[i]]);
  distinct := 0;
  lastSym := 0;
  for var s := 0 to 255 do
    if count[s] > 0 then begin
      Inc(distinct);
      lastSym := s;
    end;
  if distinct = 1 then begin
    rleSection;
    exit;
  end;
  if litCnt < 32 then begin             // too small for a tree to pay off
    rawSection;
    exit;
  end;
  hufLengths(count, lastSym + 1, hlen);
  maxBits := 0;
  for var s := 0 to lastSym do
    if hlen[s] > maxBits then maxBits := hlen[s];
  // weights from lengths; build canonical codes the decoder way
  for var s := 0 to lastSym do
    if hlen[s] > 0 then
      weights[s] := maxBits + 1 - hlen[s]
    else
      weights[s] := 0;
  hufCanonCodes(hlen, lastSym, maxBits, code);
  if not buildTreeDesc then begin
    rawSection;
    exit;
  end;
  // the previous block's tree may beat a fresh tree + its description
  litType := 2;
  if pHufLive then begin
    var bitsOld: QWord := 0;
    var bitsNew: QWord := QWord(treeLen) * 8;
    var oldOk: Boolean := true;
    for var s := 0 to lastSym do
      if count[s] > 0 then begin
        if pHufLen[s] = 0 then begin
          oldOk := false;
          break;
        end;
        bitsOld := bitsOld + QWord(count[s]) * pHufLen[s];
        bitsNew := bitsNew + QWord(count[s]) * hlen[s];
      end;
    if oldOk and (bitsOld <= bitsNew) then begin
      litType := 3;
      treeLen := 0;
      for var s := 0 to 255 do begin
        hlen[s] := pHufLen[s];
        code[s] := pHufCode[s];
      end;
    end;
  end;
  // pick the stream layout
  fourStreams := litCnt > 256;
  if litCnt < 6 then fourStreams := false;
  // worst case before the profitability check: 11 bits a literal
  SetLength(streams, litCnt + (litCnt shr 1) + 128);
  totalStreams := 0;
  if not fourStreams then begin
    totalStreams := putStream(0, litCnt, @streams[0], 0);
  end
  else begin
    per := (litCnt + 3) div 4;
    lastN := litCnt - 3 * per;
    s1n := putStream(0, per, @streams[0], 6);
    s2n := putStream(per, per, @streams[0], 6 + s1n);
    s3n := putStream(2 * per, per, @streams[0], 6 + s1n + s2n);
    s4n := putStream(3 * per, lastN, @streams[0], 6 + s1n + s2n + s3n);
    if (s1n > 65535) or (s2n > 65535) or (s3n > 65535) then begin
      rawSection;
      exit;
    end;
    streams[0] := Byte(s1n);
    streams[1] := Byte(s1n shr 8);
    streams[2] := Byte(s2n);
    streams[3] := Byte(s2n shr 8);
    streams[4] := Byte(s3n);
    streams[5] := Byte(s3n shr 8);
    totalStreams := 6 + s1n + s2n + s3n + s4n;
  end;
  comp := treeLen + totalStreams;
  // header layout by sizes
  if (not fourStreams) and (litCnt <= 1023) and (comp <= 1023) then begin
    v := QWord(litType) or (QWord(0) shl 2) or (QWord(litCnt) shl 4) or
      (QWord(comp) shl 14);
    litSec[0] := Byte(v);
    litSec[1] := Byte(v shr 8);
    litSec[2] := Byte(v shr 16);
    hdr := 3;
  end
  else if fourStreams and (litCnt <= 1023) and (comp <= 1023) then begin
    v := QWord(litType) or (QWord(1) shl 2) or (QWord(litCnt) shl 4) or
      (QWord(comp) shl 14);
    litSec[0] := Byte(v);
    litSec[1] := Byte(v shr 8);
    litSec[2] := Byte(v shr 16);
    hdr := 3;
  end
  else if fourStreams and (litCnt <= 16383) and (comp <= 16383) then begin
    v := QWord(litType) or (QWord(2) shl 2) or (QWord(litCnt) shl 4) or
      (QWord(comp) shl 18);
    litSec[0] := Byte(v);
    litSec[1] := Byte(v shr 8);
    litSec[2] := Byte(v shr 16);
    litSec[3] := Byte(v shr 24);
    hdr := 4;
  end
  else if fourStreams then begin
    v := QWord(litType) or (QWord(3) shl 2) or (QWord(litCnt) shl 4) or
      (QWord(comp) shl 22);
    litSec[0] := Byte(v);
    litSec[1] := Byte(v shr 8);
    litSec[2] := Byte(v shr 16);
    litSec[3] := Byte(v shr 24);
    litSec[4] := Byte(v shr 32);
    hdr := 5;
  end
  else begin
    // single stream that outgrew the 10-bit fields
    rawSection;
    exit;
  end;
  // worth it at all?
  if hdr + comp >= litCnt + 3 then begin
    rawSection;
    exit;
  end;
  if treeLen > 0 then
    Move(treeDesc[0], litSec[hdr], treeLen);
  Move(streams[0], litSec[hdr + treeLen], totalStreams);
  if litType = 2 then begin
    // the decoder remembers this tree now; so do we
    for var s := 0 to 255 do begin
      pHufLen[s] := 0;
      pHufCode[s] := 0;
    end;
    for var s := 0 to lastSym do begin
      pHufLen[s] := hlen[s];
      pHufCode[s] := code[s];
    end;
    pHufLive := true;
  end;
  result := hdr + comp;
end;

{ sequences section appended to dst at `at`; returns new end offset }
function TZstdEncoder.buildSequences(dst: TByteArray; at: SizeInt): SizeInt;
var
  cLL: array[0..35] of LongWord;
  cML: array[0..52] of LongWord;
  cOF: array[0..31] of LongWord;
  codeLL, codeML, codeOF: array of Byte;
  nLL, nML, nOF: array[0..63] of SmallInt;
  encLL, encML, encOF: TFseEnc;
  modeLL, modeML, modeOF: Integer;
  accLL, accML, accOF: Integer;
  bw: TForwBits;
  stLL, stML, stOF: Integer;

  { pick predefined / rle / fresh fse / repeat for channel ch (0=LL,
    1=OF, 2=ML); for rle the lone symbol value rides in accOut }
  function chooseMode(ch: Integer; const cnt: array of LongWord;
    nSym: Integer; const defNorm: array of SmallInt;
    defNSym, defAcc, maxAcc: Integer; total: Integer;
    out norm: array of SmallInt; out accOut: Integer): Integer;
  var
    distinct, last, lone: Integer;
    costDef, costFse, costRep: QWord;
    descBytes: SizeInt;
    tmp: array[0..255] of Byte;
    ok: Boolean;
  begin
    distinct := 0;
    last := 0;
    lone := 0;
    for var s := 0 to nSym - 1 do
      if cnt[s] > 0 then begin
        Inc(distinct);
        last := s;
        lone := s;
      end;
    if distinct = 1 then begin
      if (pSeqKind[ch] = 2) and (pSeqRle[ch] = lone) then
        exit(3);                     // same single symbol: free repeat
      accOut := lone;                // symbol value rides in accOut
      exit(1);
    end;
    // predefined cost (invalid if symbols outside the default range)
    costDef := High(QWord);
    if last < defNSym then
      costDef := fseCost(cnt, defNorm, defNSym, defAcc);
    // last block's table, free of description bytes
    costRep := High(QWord);
    if pSeqKind[ch] = 1 then
      costRep := fseCost(cnt, pSeqNorm[ch], nSym, pSeqAcc[ch]);
    // custom table cost
    costFse := High(QWord);
    accOut := maxAcc;
    if total > 1 then begin
      var sb: Integer := bitTop(total - 1) - 2;
      if sb < accOut then accOut := sb;
    end;
    var minAcc: Integer := bitTop(LongWord(distinct - 1)) + 1;
    if accOut < minAcc then accOut := minAcc;
    if accOut < 5 then accOut := 5;
    if accOut > maxAcc then accOut := maxAcc;
    ok := fseNormalize(cnt, total, nSym, accOut, norm);
    if ok then begin
      descBytes := fseWriteSpec(norm, last + 1, accOut, @tmp[0], 0);
      costFse := fseCost(cnt, norm, nSym, accOut) + QWord(descBytes) * 8 * 256;
    end;
    if (costRep <= costFse) and (costRep <= costDef) then
      exit(3);
    if (costDef = High(QWord)) and not ok then
      exit(-1);                      // nothing fits; raw block upstream
    if costDef <= costFse then begin
      for var s := 0 to nSym - 1 do
        if s < defNSym then norm[s] := defNorm[s] else norm[s] := 0;
      accOut := defAcc;
      exit(0);
    end;
    result := 2;
  end;

  { remember what the decoder's tables now hold for this channel }
  procedure keepTable(ch, mode: Integer; const enc: TFseEnc;
    const norm: array of SmallInt; nSym, acc, rleSym: Integer);
  begin
    if mode = 3 then exit;
    if mode = 1 then begin
      pSeqKind[ch] := 2;
      pSeqRle[ch] := rleSym;
    end
    else begin
      pSeqKind[ch] := 1;
      for var s := 0 to 63 do
        if s < nSym then pSeqNorm[ch][s] := norm[s] else pSeqNorm[ch][s] := 0;
      pSeqAcc[ch] := acc;
    end;
    pSeqEnc[ch] := enc;
  end;

  { single-state table, accuracy log 0: every operation moves zero bits }
  procedure rleTable(var enc: TFseEnc; rleSym: Integer);
  begin
    enc.accLog := 0;
    SetLength(enc.stateTab, 1);
    enc.stateTab[0] := 1;
    SetLength(enc.dBits, rleSym + 1);
    SetLength(enc.dState, rleSym + 1);
    enc.dBits[rleSym] := -1;       // (0 shl 16) - tableSize
    enc.dState[rleSym] := -1;
  end;

var
  total: Integer;
  here: SizeInt;
  ofvBits: Integer;
begin
  total := seqCnt;
  here := at;
  // sequence count (1-3 bytes)
  if total < 128 then begin
    dst[here] := Byte(total);
    Inc(here);
  end
  else if total < $7F00 then begin
    dst[here] := Byte((total shr 8) + $80);
    dst[here + 1] := Byte(total);
    Inc(here, 2);
  end
  else begin
    dst[here] := 255;
    dst[here + 1] := Byte(total - $7F00);
    dst[here + 2] := Byte((total - $7F00) shr 8);
    Inc(here, 3);
  end;
  if total = 0 then exit(here);
  // per-sequence codes and histograms
  SetLength(codeLL, total);
  SetLength(codeML, total);
  SetLength(codeOF, total);
  FillChar(cLL, SizeOf(cLL), 0);
  FillChar(cML, SizeOf(cML), 0);
  FillChar(cOF, SizeOf(cOF), 0);
  for var i := 0 to total - 1 do begin
    codeLL[i] := llCode(seqLL[i]);
    codeML[i] := mlCode(seqML[i] - 3);
    codeOF[i] := bitTop(seqOV[i]);
    Inc(cLL[codeLL[i]]);
    Inc(cML[codeML[i]]);
    Inc(cOF[codeOF[i]]);
  end;
  if statsOn then begin
    for var s := 0 to 35 do Inc(statLL[s], cLL[s]);
    for var s := 0 to 31 do Inc(statOF[s], cOF[s]);
    for var s := 0 to 52 do Inc(statML[s], cML[s]);
    Inc(statSeqs, total);
  end;
  modeLL := chooseMode(0, cLL, 36, DEF_LL, 36, 6, 9, total, nLL, accLL);
  modeOF := chooseMode(1, cOF, 32, DEF_OF, 29, 5, 8, total, nOF, accOF);
  modeML := chooseMode(2, cML, 53, DEF_ML, 53, 6, 9, total, nML, accML);
  if (modeLL < 0) or (modeOF < 0) or (modeML < 0) then exit(-1);
  dst[here] := Byte((modeLL shl 6) or (modeOF shl 4) or (modeML shl 2));
  Inc(here);
  // table payloads in LL, OF, ML order
  case modeLL of
    1: begin
      dst[here] := Byte(accLL);   // the lone symbol
      rleTable(encLL, accLL);
      Inc(here);
    end;
    3: encLL := pSeqEnc[0];
    else begin
      if modeLL = 2 then
        Inc(here, fseWriteSpec(nLL, 36, accLL, @dst[0], here));
      fseBuildEnc(encLL, nLL, 36, accLL);
    end;
  end;
  keepTable(0, modeLL, encLL, nLL, 36, accLL, accLL);
  case modeOF of
    1: begin
      dst[here] := Byte(accOF);
      rleTable(encOF, accOF);
      Inc(here);
    end;
    3: encOF := pSeqEnc[1];
    else begin
      if modeOF = 2 then
        Inc(here, fseWriteSpec(nOF, 32, accOF, @dst[0], here));
      fseBuildEnc(encOF, nOF, 32, accOF);
    end;
  end;
  keepTable(1, modeOF, encOF, nOF, 32, accOF, accOF);
  case modeML of
    1: begin
      dst[here] := Byte(accML);
      rleTable(encML, accML);
      Inc(here);
    end;
    3: encML := pSeqEnc[2];
    else begin
      if modeML = 2 then
        Inc(here, fseWriteSpec(nML, 53, accML, @dst[0], here));
      fseBuildEnc(encML, nML, 53, accML);
    end;
  end;
  keepTable(2, modeML, encML, nML, 53, accML, accML);
  // interleaved bitstream, written forward, read backward
  bw.Open(@dst[0], here);
  stML := fseEncInit(encML, codeML[total - 1]);
  stOF := fseEncInit(encOF, codeOF[total - 1]);
  stLL := fseEncInit(encLL, codeLL[total - 1]);
  bw.Put(seqLL[total - 1] - LL_BASE[codeLL[total - 1]],
    LL_XTRA[codeLL[total - 1]]);
  bw.Put(seqML[total - 1] - ML_BASE[codeML[total - 1]],
    ML_XTRA[codeML[total - 1]]);
  ofvBits := codeOF[total - 1];
  bw.Put(seqOV[total - 1] - (LongWord(1) shl ofvBits), ofvBits);
  for var n := total - 2 downto 0 do begin
    fseEncPush(encOF, bw, stOF, codeOF[n]);
    fseEncPush(encML, bw, stML, codeML[n]);
    fseEncPush(encLL, bw, stLL, codeLL[n]);
    bw.Put(seqLL[n] - LL_BASE[codeLL[n]], LL_XTRA[codeLL[n]]);
    bw.Put(seqML[n] - ML_BASE[codeML[n]], ML_XTRA[codeML[n]]);
    ofvBits := codeOF[n];
    bw.Put(seqOV[n] - (LongWord(1) shl ofvBits), ofvBits);
  end;
  fseEncFlush(encML, bw, stML);
  fseEncFlush(encOF, bw, stOF);
  fseEncFlush(encLL, bw, stLL);
  bw.Close;
  result := bw.at;
end;

{ assemble and emit one block from the gathered literals + sequences }
procedure TZstdEncoder.flushBlock(srcLen: SizeInt; isLast: Boolean);
var
  litLen, bodyLen: SizeInt;
  bh: LongWord;
  srcAt: SizeInt;
  allSame: Boolean;
begin
  srcAt := procPos - srcLen;
  if statsOn then
    for var i := 0 to litCnt - 1 do
      Inc(statLit[litBuf[i]]);
  // RLE block when the whole source is one byte value
  allSame := srcLen > 3;
  for var i := srcAt + 1 to srcAt + srcLen - 1 do
    if win[i] <> win[srcAt] then begin
      allSame := false;
      break;
    end;
  if allSame then begin
    bh := LongWord(Ord(isLast)) or (1 shl 1) or (LongWord(srcLen) shl 3);
    emitByte(Byte(bh));
    emitByte(Byte(bh shr 8));
    emitByte(Byte(bh shr 16));
    emitByte(win[srcAt]);
    litCnt := 0;
    seqCnt := 0;
    exit;
  end;
  litLen := buildLiterals;
  bodyLen := -1;
  if litLen > 0 then begin
    Move(litSec[0], scratch[0], litLen);
    bodyLen := buildSequences(scratch, litLen);
  end;
  if (bodyLen < 0) or (bodyLen >= srcLen) or (bodyLen > blockCap) then begin
    // raw block: the tables baked above never reached the decoder, so
    // stop relying on them for repeat/treeless coding
    pHufLive := false;
    pSeqKind[0] := 0;
    pSeqKind[1] := 0;
    pSeqKind[2] := 0;
    // not worth it: raw block
    bh := LongWord(Ord(isLast)) or (LongWord(srcLen) shl 3);
    emitByte(Byte(bh));
    emitByte(Byte(bh shr 8));
    emitByte(Byte(bh shr 16));
    if srcLen > 0 then
      emit(win[srcAt], srcLen);
  end
  else begin
    bh := LongWord(Ord(isLast)) or (2 shl 1) or (LongWord(bodyLen) shl 3);
    emitByte(Byte(bh));
    emitByte(Byte(bh shr 8));
    emitByte(Byte(bh shr 16));
    emit(scratch[0], bodyLen);
  end;
  litCnt := 0;
  seqCnt := 0;
end;

{ process buffered input into blocks; final = flush everything }
procedure TZstdEncoder.compressStep(final: Boolean);
begin
  while winLen - procPos >= BLOCK_SRC do begin
    parseBlock(procPos + blockCap);
    flushBlock(blockCap, final and (winLen = procPos));
    slideWindow;
    report;
  end;
  if final then
    while winLen - procPos > 0 do begin
      var step: SizeInt := winLen - procPos;
      if step > blockCap then step := blockCap;
      parseBlock(procPos + step);
      flushBlock(step, winLen = procPos);
    end;
end;

procedure TZstdEncoder.Update(Data: Pointer; Len: SizeInt);
begin
  if done or (Len <= 0) then exit;
  xxFeed(Data, Len);
  Inc(consumed, Len);
  if winLen + Len > Length(win) then begin
    var want: SizeInt := winLen + Len;
    if want < 2 * Length(win) then want := 2 * Length(win);
    if want < 1024 * 1024 then want := 1024 * 1024;
    SetLength(win, want);
  end;
  Move(Data^, win[winLen], Len);
  Inc(winLen, Len);
  if not started then begin
    // start an unknown-size frame once enough input piled up
    if consumed >= QWord((SizeInt(1) shl wlog) + 8 * BLOCK_SRC) then
      startFrame(false, 0)
    else
      exit;
  end;
  compressStep(false);
  report;
end;

procedure TZstdEncoder.Update(const Data: array of Byte);
begin
  if Length(Data) > 0 then
    Update(@Data[0], Length(Data));
end;

procedure TZstdEncoder.Finalize;
var
  sum: LongWord;
begin
  if done then exit;
  if err <> 0 then begin
    done := true;
    exit;
  end;
  if not started then
    startFrame(true, consumed);
  if winLen = procPos then begin
    // no remaining payload: close with an empty raw last block
    emitByte($01);
    emitByte($00);
    emitByte($00);
  end
  else
    compressStep(true);
  if withSum then begin
    sum := LongWord(xxDigest and $FFFFFFFF);
    emit(sum, 4);
  end;
  done := true;
  report;
end;

{ ---------------------------------------------------------------- }
{ one-shot helper                                                   }
{ ---------------------------------------------------------------- }

function ZstdPack(Data: Pointer; Len: SizeInt; ALevel: Integer; AChecksum: Boolean): TByteArray;
begin
  result := nil;
  var c := autofree TZstdEncoder.Create;
  c.Init(ALevel, AChecksum);
  c.totalbytes := Len;
  if Len > 0 then
    c.Update(Data, Len);
  c.Finalize;
  SetLength(result, c.buflen);
  if c.buflen > 0 then
    Move(c.buf[0], result[0], c.buflen);
end;

function ZstdPack(const Source: array of Byte; ALevel: Integer; AChecksum: Boolean): TByteArray;
begin
  if Length(Source) = 0 then
    result := ZstdPack(nil, 0, ALevel, AChecksum)
  else
    result := ZstdPack(@Source[0], Length(Source), ALevel, AChecksum);
end;

function ZstdPack(Data: Pointer; Len: SizeInt; Dict: Pointer; DictLen: SizeInt; ALevel: Integer; AChecksum: Boolean): TByteArray;
begin
  result := nil;
  ZstdPackLastError := 0;
  var c := autofree TZstdEncoder.Create;
  c.Init(ALevel, AChecksum);
  c.UseDictionary(Dict, DictLen);
  c.totalbytes := Len;
  if Len > 0 then
    c.Update(Data, Len);
  c.Finalize;
  if c.err <> 0 then begin
    ZstdPackLastError := c.err;
    exit;
  end;
  SetLength(result, c.buflen);
  if c.buflen > 0 then
    Move(c.buf[0], result[0], c.buflen);
end;

function ZstdPack(const Source: array of Byte; const Dict: array of Byte; ALevel: Integer; AChecksum: Boolean): TByteArray;
begin
  result := nil;
  ZstdPackLastError := 1;
  if Length(Dict) = 0 then exit;
  if Length(Source) = 0 then
    result := ZstdPack(nil, 0, @Dict[0], Length(Dict), ALevel, AChecksum)
  else
    result := ZstdPack(@Source[0], Length(Source), @Dict[0], Length(Dict), ALevel, AChecksum);
end;

function ZstdPackStr(const Source: String; ALevel: Integer; AChecksum: Boolean): String;
var
  r: TByteArray;
begin
  if Length(Source) = 0 then
    r := ZstdPack(nil, 0, ALevel, AChecksum)
  else
    r := ZstdPack(@Source[1], Length(Source), ALevel, AChecksum);
  SetLength(result, Length(r));
  if Length(r) > 0 then Move(r[0], result[1], Length(r));
end;

function ZstdPackStr(const Source: String; const Dict: String; ALevel: Integer; AChecksum: Boolean): String;
var
  r: TByteArray;
begin
  result := '';
  ZstdPackLastError := 1;
  if Length(Dict) = 0 then exit;
  if Length(Source) = 0 then
    r := ZstdPack(nil, 0, @Dict[1], Length(Dict), ALevel, AChecksum)
  else
    r := ZstdPack(@Source[1], Length(Source), @Dict[1], Length(Dict), ALevel, AChecksum);
  SetLength(result, Length(r));
  if Length(r) > 0 then Move(r[0], result[1], Length(r));
end;

{ content + histograms -> a structured dictionary blob }
function ZstdBuildDictionary(const content: array of Byte; const litFreq: array of LongWord; const llFreq: array of LongWord; const ofFreq: array of LongWord; const mlFreq: array of LongWord; ADictId: LongWord): TByteArray;
var
  hlen: array[0..255] of Byte;
  weights: array[0..255] of Byte;
  blob: array[0..8191] of Byte;
  norm: array[0..63] of SmallInt;
  at: SizeInt;
  maxBits, lastSym, used: Integer;

  function putFse(const f: array of LongWord; nSym, maxAcc: Integer): Boolean;
  var
    total, distinct, acc, minAcc: Integer;
  begin
    result := false;
    total := 0;
    distinct := 0;
    for var s := 0 to nSym - 1 do begin
      Inc(total, f[s]);
      if f[s] > 0 then Inc(distinct);
    end;
    if (total < 2) or (distinct < 2) then exit;
    acc := maxAcc;
    var sb: Integer := bitTop(total - 1) - 2;
    if sb < acc then acc := sb;
    minAcc := bitTop(LongWord(distinct - 1)) + 1;
    if acc < minAcc then acc := minAcc;
    if acc < 5 then acc := 5;
    if acc > maxAcc then acc := maxAcc;
    if not fseNormalize(f, total, nSym, acc, norm) then exit;
    Inc(at, fseWriteSpec(norm, nSym, acc, @blob[0], at));
    result := true;
  end;

begin
  result := nil;
  if (Length(content) < 8) or (ADictId = 0) then exit;
  initTables;
  // literals tree
  if hufLengths(litFreq, 256, hlen) < 2 then exit;
  maxBits := 0;
  lastSym := 0;
  for var s := 0 to 255 do
    if hlen[s] > 0 then begin
      if hlen[s] > maxBits then maxBits := hlen[s];
      lastSym := s;
    end;
  for var s := 0 to 255 do
    if hlen[s] > 0 then
      weights[s] := maxBits + 1 - hlen[s]
    else
      weights[s] := 0;
  at := 0;
  used := hufWriteDesc(weights, lastSym, @blob[0]);
  if used = 0 then exit;
  Inc(at, used);
  // fse tables in offsets, match lengths, literal lengths order
  if not putFse(ofFreq, 32, 8) then exit;
  if not putFse(mlFreq, 53, 9) then exit;
  if not putFse(llFreq, 36, 9) then exit;
  SetLength(result, 8 + at + 12 + Length(content));
  PLongWord(@result[0])^ := MAGIC_DICT;
  PLongWord(@result[4])^ := ADictId;
  Move(blob[0], result[8], at);
  // starting repeat offsets; 1/4/8 are always sound
  PLongWord(@result[8 + at])^ := 1;
  PLongWord(@result[8 + at + 4])^ := 4;
  PLongWord(@result[8 + at + 8])^ := 8;
  Move(content[0], result[8 + at + 12], Length(content));
end;

end.
