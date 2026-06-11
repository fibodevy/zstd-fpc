{ zstd-fpc: Zstandard (RFC 8878) written in Pascal.
  Copyright (c) 2026 @fibodevy / https://github.com/fibodevy/zstd-fpc
  MIT licensed (see LICENSE). Free to use and modify; keep this notice
  and the link when you redistribute the sources. }

program zstd;

{ command-line Zstandard compressor/decompressor

    zstd -c [-1..-9] [-D dict] <input> [output]   compress (level 6)
    zstd -d [-D dict] <input> [output]            decompress
    zstd -train [-s kb] <out.dict> <samples...>   train a dictionary

  Without an explicit output, -c appends SUFFIX (".zst") to the input
  name and -d strips it (and insists on one being there). Files are
  streamed in 1 MB chunks, so memory stays flat regardless of file
  size. An existing output file prompts before overwriting.

  -D loads a dictionary (raw bytes or a trained .dict) for both
  directions; -train builds a structured dictionary from the given
  sample files (a single sample file gets sliced into 4 KB pieces). }

{$mode unleashed}

uses SysUtils, Classes, zstdencoder, zstddecoder, zstdtrainer;

const
  CHUNK = 1024 * 1024;
  SUFFIX = '.zst';

procedure usage;
begin
  writeln('zstd - Zstandard (RFC 8878) compressor/decompressor');
  writeln;
  writeln('usage:');
  writeln('  zstd -c [-1..-9] [-D dict] <input> [output]   compress (level 6)');
  writeln('  zstd -d [-D dict] <input> [output]            decompress');
  writeln('  zstd -train [-s kb] <out.dict> <samples...>   train a dictionary');
  writeln;
  writeln('without an output name, -c writes <input>'+SUFFIX+' and -d strips');
  writeln('the '+SUFFIX+' suffix from the input name; -D uses a dictionary');
  writeln('(raw bytes or trained); -train default size is 110 kb');
  halt(2);
end;

procedure die(const msg: String);
begin
  writeln('error: ', msg);
  halt(1);
end;

function errName(code: Integer): String;
begin
  result := match code of
    ZSTD_E_MAGIC:      'not a zstandard stream';
    ZSTD_E_HEADER:     'malformed frame header';
    ZSTD_E_WINDOW:     'window size above the accepted limit';
    ZSTD_E_DICTIONARY: 'stream requires an external dictionary';
    ZSTD_E_BLOCK:      'corrupt block header';
    ZSTD_E_LITERALS:   'corrupt literals section';
    ZSTD_E_HUFFMAN:    'corrupt huffman data';
    ZSTD_E_FSE:        'corrupt fse table description';
    ZSTD_E_SEQUENCES:  'corrupt sequences section';
    ZSTD_E_OFFSET:     'match offset beyond decoded history';
    ZSTD_E_CHECKSUM:   'content checksum mismatch';
    ZSTD_E_TRUNCATED:  'input ends in the middle of a frame';
    ZSTD_E_SIZE:       'decoded size contradicts the frame header';
  else 'error code '+IntToStr(code);
end;

procedure confirmOverwrite(const fn: String);
var
  ans, clean: String;
  c: Char;
begin
  if not FileExists(fn) then exit;
  write('output "', fn, '" exists, overwrite? [y/N] ');
  readln(ans);
  // keep just the letters: piped input can carry byte order marks or
  // their codepage-converted leftovers around the actual answer
  clean := '';
  for c in ans do
    case c of
      'a'..'z': clean := clean + c;
      'A'..'Z': clean := clean + chr(ord(c) + 32);
    end;
  if(clean <> 'y') and (clean <> 'yes') then begin
    writeln('aborted');
    halt(1);
  end;
end;

procedure showProgress(percent: Integer);
begin
  write(#13, percent:3, '%');
end;

var
  doCompress: Boolean;
  level: Integer = 6;
  trainKb: Integer = 110;
  dictFn: String = '';
  inFn, outFn: String;
  posArgs: array of String;
  dict: zstdencoder.TByteArray;
  fin, fout: TFileStream;
  data: array of Byte;
  got: SizeInt;
  inBytes, outBytes: Int64;
  t0: QWord;

procedure pump(const part; len: SizeInt);
begin
  if len > 0 then begin
    fout.WriteBuffer(part, len);
    inc(outBytes, len);
  end;
end;

function loadWhole(const fn: String): zstdencoder.TByteArray;
begin
  result := nil;
  var fs := autofree TFileStream.Create(fn, fmOpenRead or fmShareDenyWrite);
  setlength(result, fs.size);
  if fs.size > 0 then fs.ReadBuffer(result[0], fs.size);
end;

{ resolve one sample argument into concrete file paths: a directory is
  walked recursively, a pattern with * or ? yields its matches (matched
  subdirectories are walked too), anything else is taken verbatim.
  Symlinked directories are skipped so the walk can't loop. Appends to
  files. }
procedure expandSampleArg(const arg: String; var files: array of String; var nF: Integer);

  procedure add(const fn: String);
  begin
    if nF > high(files) then die('too many sample files (limit '+IntToStr(length(files))+')');
    files[nF] := fn;
    inc(nF);
  end;

  // every file under dir, at any depth
  procedure walk(const dir: String);
  var
    sr: TSearchRec;
    base: String;
  begin
    base := IncludeTrailingPathDelimiter(dir);
    if FindFirst(base+'*', faAnyFile, sr) = 0 then begin
      try
        repeat
          if(sr.name = '.') or (sr.name = '..') then continue;
          if(sr.Attr and faSymLink) <> 0 then continue;
          if(sr.Attr and faDirectory) <> 0 then walk(base + sr.name)
          else add(base + sr.name);
        until FindNext(sr) <> 0;
      finally
        FindClose(sr);
      end;
    end;
  end;

  // entries matching a glob: files added, matched subdirectories walked
  procedure scan(const pattern: String);
  var
    sr: TSearchRec;
    dir: String;
  begin
    dir := ExtractFilePath(pattern);
    if FindFirst(pattern, faAnyFile, sr) = 0 then begin
      try
        repeat
          if(sr.name = '.') or (sr.name = '..') then continue;
          if(sr.Attr and faDirectory) <> 0 then begin
            if(sr.Attr and faSymLink) = 0 then walk(dir + sr.name);
          end else
            add(dir + sr.name);
        until FindNext(sr) <> 0;
      finally
        FindClose(sr);
      end;
    end;
  end;

begin
  if DirectoryExists(arg) then walk(arg)
  else if(Pos('*', arg) > 0) or (Pos('?', arg) > 0) then scan(arg)
  else begin
    if not FileExists(arg) then die('sample "'+arg+'" not found');
    add(arg);
  end;
end;

procedure runTrain;
var
  samples: array of zstdencoder.TByteArray;
  files: array of String;
  nF, nS: Integer;
  trained: zstdencoder.TByteArray;
  fs: TFileStream;
begin
  if length(posArgs) < 2 then usage;
  outFn := posArgs[0];
  // expand every sample argument (recursive dirs, globs, plain files)
  setlength(files, 1 shl 18);
  nF := 0;
  for var i := 1 to high(posArgs) do expandSampleArg(posArgs[i], files, nF);
  if nF = 0 then die('no sample files matched');
  setlength(files, nF);
  // deterministic dictionary: sort the file set before training
  for var i := 1 to nF - 1 do begin
    var key := files[i];
    var j := i - 1;
    while(j >= 0) and (CompareText(files[j], key) > 0) do begin
      files[j + 1] := files[j];
      dec(j);
    end;
    files[j + 1] := key;
  end;
  nS := 0;
  samples := nil;
  if nF = 1 then begin
    // one sample file: slice it so the trainer sees many small bodies
    var whole := loadWhole(files[0]);
    var at: SizeInt := 0;
    setlength(samples, (length(whole) + 4095) div 4096);
    while at < length(whole) do begin
      var n: SizeInt := 4096;
      if at + n > length(whole) then n := length(whole) - at;
      setlength(samples[nS], n);
      Move(whole[at], samples[nS][0], n);
      inc(nS);
      inc(at, n);
    end;
  end else begin
    setlength(samples, nF);
    for var i := 0 to nF - 1 do begin
      samples[nS] := loadWhole(files[i]);
      inc(nS);
    end;
  end;
  setlength(samples, nS);
  trained := ZstdTrain(samples, trainKb * 1024);
  if length(trained) = 0 then die('not enough sample material to train from');
  confirmOverwrite(outFn);
  fs := TFileStream.Create(outFn, fmCreate);
  fs.WriteBuffer(trained[0], length(trained));
  fs.Free;
  if nF = 1 then writeln('trained dictionary: ', length(trained), ' bytes from 1 file (', nS, ' slices) -> ', outFn)
  else writeln('trained dictionary: ', length(trained), ' bytes from ', nF, ' files -> ', outFn);
  halt(0);
end;

begin
  if ParamCount < 2 then usage;
  case ParamStr(1) of
    '-c':     doCompress := true;
    '-d':     doCompress := false;
    '-train': doCompress := false;
  else
    usage;
  end;
  // flags and positional arguments
  posArgs := nil;
  begin
    var i: Integer := 2;
    while i <= ParamCount do begin
      var a := ParamStr(i);
      if(a = '-D') and (i < ParamCount) then begin
        dictFn := ParamStr(i + 1);
        inc(i, 2);
      end else if(a = '-s') and (i < ParamCount) then begin
        trainKb := StrToIntDef(ParamStr(i + 1), 110);
        inc(i, 2);
      end else if(length(a) = 2) and (a[1] = '-') and (a[2] in ['1'..'9']) then begin
        level := ord(a[2]) - ord('0');
        inc(i);
      end else begin
        setlength(posArgs, length(posArgs) + 1);
        posArgs[high(posArgs)] := a;
        inc(i);
      end;
    end;
  end;
  if ParamStr(1) = '-train' then runTrain;
  if(length(posArgs) < 1) or (length(posArgs) > 2) then usage;
  inFn := posArgs[0];
  if length(posArgs) = 2 then outFn := posArgs[1]
  else if doCompress then outFn := inFn+SUFFIX
  else
    // derive the output by stripping SUFFIX
    if(length(inFn) > length(SUFFIX)) and SameText(copy(inFn, length(inFn) - length(SUFFIX) + 1, length(SUFFIX)), SUFFIX) then outFn := copy(inFn, 1, length(inFn) - length(SUFFIX))
    else die('input has no '+SUFFIX+' suffix; give the output name explicitly');
  if not FileExists(inFn) then die('input "'+inFn+'" not found');
  dict := nil;
  if dictFn <> '' then begin
    if not FileExists(dictFn) then die('dictionary "'+dictFn+'" not found');
    dict := loadWhole(dictFn);
  end;
  if ExpandFileName(inFn) = ExpandFileName(outFn) then die('input and output are the same file');
  confirmOverwrite(outFn);

  fin := TFileStream.Create(inFn, fmOpenRead or fmShareDenyWrite);
  try
    fout := TFileStream.Create(outFn, fmCreate);
  except
    on E: Exception do begin
      fin.Free;
      die('cannot create "'+outFn+'": '+E.message);
      exit;
    end;
  end;
  setlength(data, CHUNK);
  inBytes := fin.size;
  outBytes := 0;
  t0 := GetTickCount64;

  if doCompress then begin
    var c := TZstdEncoder.Create;
    c.Init(level);
    if dict <> nil then begin
      c.UseDictionary(dict);
      if c.err <> 0 then begin
        fout.Free;
        DeleteFile(outFn);
        die('dictionary "'+dictFn+'" is not usable');
      end;
    end;
    c.totalbytes := inBytes;
    c.onProgress(procedure(p:Integer)
    begin
      showProgress(p);
    end);
    repeat
      got := fin.read(data[0], CHUNK);
      if got > 0 then begin
        c.Update(@data[0], got);
        if c.buflen > 0 then begin
          pump(c.buf[0], c.buflen);
          c.ResetBuf;
        end;
      end;
    until got < CHUNK;
    c.Finalize;
    if c.buflen > 0 then pump(c.buf[0], c.buflen);
    c.Free;
    write(#13);
    writeln('compressed: ', inBytes, ' -> ', outBytes, ' bytes (', (outBytes * 1000 div (inBytes + ord(inBytes = 0))) / 10:0:1, '%, level ', level, ', ', GetTickCount64 - t0, ' ms)');
  end else begin
    var d := TZstdDecoder.Create;
    d.Init;
    if dict <> nil then begin
      d.UseDictionary(dict);
      if d.err <> ZSTD_OK then begin
        fout.Free;
        DeleteFile(outFn);
        die('dictionary "'+dictFn+'" is not usable');
      end;
    end;
    d.onProgress(procedure(p:Integer)
    begin
      showProgress(p);
    end);
    repeat
      got := fin.read(data[0], CHUNK);
      if got > 0 then begin
        d.Update(@data[0], got);
        if d.err <> ZSTD_OK then break;
        if d.buflen > 0 then begin
          pump(d.buf[0], d.buflen);
          d.ResetBuf;
        end;
      end;
    until got < CHUNK;
    d.Finalize;
    if d.err <> ZSTD_OK then begin
      var code := d.err;
      d.Free;
      fin.Free;
      fout.Free;
      write(#13);
      DeleteFile(outFn);
      die(errName(code));
    end;
    if d.buflen > 0 then pump(d.buf[0], d.buflen);
    d.Free;
    write(#13);
    writeln('decompressed: ', inBytes, ' -> ', outBytes, ' bytes (', GetTickCount64 - t0, ' ms)');
  end;
  fin.Free;
  fout.Free;
end.

