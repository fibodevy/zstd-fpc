{ zstd-fpc: Zstandard (RFC 8878) written in Pascal.
  Copyright (c) 2026 @fibodevy / https://github.com/fibodevy/zstd-fpc
  MIT licensed (see LICENSE). Free to use and modify; keep this notice
  and the link when you redistribute the sources. }

unit zstdtrainer;

{ trains a structured Zstandard dictionary from sample buffers.

  Content selection works the way fast cover trainers do: every 8-byte
  window of the samples is hashed into a frequency table, then the
  samples are walked epoch by epoch and each epoch contributes its
  highest-scoring 1 KB segment (score = sum of dmer frequencies inside,
  with chosen dmers zeroed so later epochs pick complementary
  material). The best segments land at the end of the dictionary,
  closest to the data that will reference them.

  Entropy tables come from compressing the samples against the chosen
  content with the histogram capture in zstdencoder, smoothed so every
  literal and code stays representable, and assembled by
  ZstdBuildDictionary into the standard dictionary format
  (magic EC30A437) that any zstd implementation loads.

  usage:
    dict := ZstdTrain(samples);            // ~110 KB dictionary
    dict := ZstdTrain(samples, 16 * 1024); // explicit size

  Returns nil when the samples are too thin to train from. }

{$mode unleashed}
{$ifndef ZSTD_CHECKS}{$R-}{$Q-}{$endif}

interface

uses zstdencoder;

function ZstdTrain(const samples: array of TByteArray; dictSize: SizeInt = 110 * 1024; ADictId: LongWord = 0): TByteArray;

implementation

const
  DMER = 8;                      // hashed window
  SEG = 1024;                    // segment granularity
  FBITS = 18;                    // frequency table size
  TRAIN_CAP = 64 * 1024 * 1024;  // training material cap

{$push}{$Q-}{$R-}  // multiplicative hashing wraps mod 2^64 by design

function dmerHash(p: PByte): LongWord; inline;
begin
  result := LongWord((QWord(PQWord(p)^ * QWord($9E3779B185EBCA87)) shr (64 - FBITS)) and ((1 shl FBITS) - 1));
end;

{$pop}

function ZstdTrain(const samples: array of TByteArray; dictSize: SizeInt; ADictId: LongWord): TByteArray;
var
  all, content: TByteArray;
  total: SizeInt;
  freq: array of LongWord;
  litFreq: array[0..255] of LongWord;
  llFreq: array[0..35] of LongWord;
  ofFreq: array[0..31] of LongWord;
  mlFreq: array[0..52] of LongWord;
begin
  result := nil;
  if dictSize < 1024 then dictSize := 1024;
  // gather the training material into one buffer
  total := 0;
  for var i := 0 to High(samples) do
    Inc(total, Length(samples[i]));
  if total > TRAIN_CAP then total := TRAIN_CAP;
  if total < 4 * SEG then exit;            // not enough to learn from
  SetLength(all, total);
  begin
    var at: SizeInt := 0;
    for var i := 0 to High(samples) do begin
      var n: SizeInt := Length(samples[i]);
      if n = 0 then continue;
      if at + n > total then n := total - at;
      if n <= 0 then break;
      Move(samples[i][0], all[at], n);
      Inc(at, n);
    end;
  end;
  // dmer frequencies
  SetLength(freq, 1 shl FBITS);
  for var i := 0 to total - DMER do
    Inc(freq[dmerHash(@all[i])]);
  // pick the best segment of every epoch, best material at the end
  begin
    var budget: SizeInt := dictSize - 768;  // entropy header reserve
    if budget > total div 2 then budget := total div 2;
    if budget < SEG then budget := SEG;
    var fill: SizeInt := budget;
    SetLength(content, budget);
    var epochs: SizeInt := budget div SEG;
    if epochs < 1 then epochs := 1;
    var epochSize: SizeInt := total div epochs;
    if epochSize < 2 * SEG then epochSize := 2 * SEG;
    var e: SizeInt := 0;
    while (fill > 0) and (e * epochSize < total - SEG) do begin
      var lo: SizeInt := e * epochSize;
      var hi: SizeInt := lo + epochSize - SEG;
      if hi > total - SEG then hi := total - SEG;
      // rolling dmer-score over the window [s, s+SEG)
      var score: Int64 := 0;
      for var i := lo to lo + SEG - DMER do
        Inc(score, freq[dmerHash(@all[i])]);
      var best: Int64 := score;
      var bestAt: SizeInt := lo;
      for var s := lo + 1 to hi do begin
        Dec(score, freq[dmerHash(@all[s - 1])]);
        Inc(score, freq[dmerHash(@all[s + SEG - DMER])]);
        if score > best then begin
          best := score;
          bestAt := s;
        end;
      end;
      var segLen: SizeInt := SEG;
      if segLen > fill then segLen := fill;
      Dec(fill, segLen);
      Move(all[bestAt], content[fill], segLen);
      // claimed dmers stop scoring for the following epochs
      for var i := bestAt to bestAt + SEG - DMER do
        freq[dmerHash(@all[i])] := 0;
      Inc(e);
    end;
    if fill > 0 then begin                 // ran out of epochs early
      Move(content[fill], content[0], budget - fill);
      SetLength(content, budget - fill);
    end;
    if Length(content) < 8 then exit;
  end;
  // histograms from compressing the samples against the content
  FillChar(litFreq, SizeOf(litFreq), 0);
  FillChar(llFreq, SizeOf(llFreq), 0);
  FillChar(ofFreq, SizeOf(ofFreq), 0);
  FillChar(mlFreq, SizeOf(mlFreq), 0);
  begin
    var fed: SizeInt := 0;
    for var i := 0 to High(samples) do begin
      if Length(samples[i]) = 0 then continue;
      if fed > TRAIN_CAP then break;
      var c := TZstdEncoder.Create;
      defer c.Free;
      c.Init(6, false);
      c.UseDictionary(content);
      c.statsOn := true;
      c.Update(samples[i]);
      c.Finalize;
      if c.err = 0 then begin
        for var s := 0 to 255 do Inc(litFreq[s], LongWord(c.statLit[s]));
        for var s := 0 to 35 do Inc(llFreq[s], LongWord(c.statLL[s]));
        for var s := 0 to 31 do Inc(ofFreq[s], LongWord(c.statOF[s]));
        for var s := 0 to 52 do Inc(mlFreq[s], LongWord(c.statML[s]));
      end;
      Inc(fed, Length(samples[i]));
    end;
  end;
  // smoothing keeps every plausible symbol representable
  for var s := 0 to 255 do Inc(litFreq[s]);
  for var s := 0 to 35 do Inc(llFreq[s]);
  for var s := 0 to 28 do Inc(ofFreq[s]);
  for var s := 0 to 52 do Inc(mlFreq[s]);
  // a derived id outside the reserved ranges, unless the caller chose
  if ADictId = 0 then begin
    var h: LongWord := 2166136261;
    for var i := 0 to High(content) do begin
      h := LongWord((QWord(h xor content[i]) * 16777619) and $FFFFFFFF);
    end;
    ADictId := 32768 + (h mod ($7FFFFFFF - 32768));
  end;
  result := ZstdBuildDictionary(content, litFreq, llFreq, ofFreq, mlFreq, ADictId);
end;

end.
