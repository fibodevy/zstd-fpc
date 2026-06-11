# zstd-fpc

Zstandard (RFC 8878) in pure Free Pascal - encoder, decoder, and a dictionary trainer, written from scratch against the format specification. The streams are fully interchangeable with the reference libzstd library (verified both ways). Built for `{$mode unleashed}`.

## Files

The codec is **three units** with no external dependencies - none of them reaches outside the implicit `System` unit. The only internal link is the trainer, which uses the encoder:

| file | role | uses |
|---|---|---|
| `zstdencoder.pas` | encoder: `TZstdEncoder` + one-shot `ZstdPack` | none |
| `zstddecoder.pas` | decoder: `TZstdDecoder` + one-shot `ZstdUnpack` | none |
| `zstdtrainer.pas` | dictionary trainer: `ZstdTrain` | zstdencoder |

Each unit can be dropped into a project on its own: the decoder alone, the encoder alone, or the encoder plus the trainer. Nothing else is required.

The repository also ships a command-line tool, `zstd.lpr` / `zstd.lpi`, that wires the three units together (see [CLI](#cli) below).

## Compress and decompress

The simplest entry points are the string one-shots: text in, a string of compressed bytes out, and back.

```pascal
uses zstdencoder, zstddecoder;

var
  z, r: String;
begin
  z := ZstdPackStr('the quick brown fox jumps over the lazy dog', 9);
  r := ZstdUnpackStr(z); // = the original text
end;
```

The same over raw bytes (`TByteArray = array of Byte`):

```pascal
uses zstdencoder, zstddecoder;

var
  src, z, r: TByteArray;
begin
  z := ZstdPack(src);           // level 6, xxhash64 checksum
  z := ZstdPack(src, 9, false); // level 9, no checksum
  r := ZstdUnpack(z);           // nil + ZstdLastError on damage
end;
```

For files or data that does not fit in memory, stream it in any chunk sizes you like and drain the output buffer as it fills:

```pascal
var
  enc: TZstdEncoder;
begin
  enc := TZstdEncoder.Create;
  enc.Init(7);                         // level 1..9 (+ optional checksum)
  enc.Update(p, n);                    // feed a chunk
  // write enc.buf[0 .. enc.buflen) to your sink, then enc.ResetBuf
  enc.Finalize;                        // flush the last bytes the same way
  enc.Free;
end;
```

```pascal
var
  dec: TZstdDecoder;
begin
  dec := TZstdDecoder.Create;
  dec.Init;                            // optional: window cap, default 128 MB
  dec.Update(p, n);
  // write dec.buf[0 .. dec.buflen) to your sink, then dec.ResetBuf
  dec.Finalize;
  if dec.err <> ZSTD_OK then ...;      // error code instead of an exception
  dec.Free;
end;
```

Both classes expose `onProgress` (percent of `totalbytes`) and report errors through the `err` field rather than raising. The one-shots set the globals `ZstdPackLastError` / `ZstdLastError`.

## Dictionaries

`UseDictionary` (called between `Init` and the first `Update`) takes either a raw blob or a structured dictionary (magic `EC30A437`). The one-shots have dictionary overloads, and the trainer builds a structured dictionary that libzstd also accepts:

```pascal
uses zstdencoder, zstddecoder, zstdtrainer;

var
  d, z: TByteArray;
begin
  d   := ZstdTrain(samples); // samples: array of TByteArray
  z   := ZstdPack(src, d, 9);
  src := ZstdUnpack(z, d);

  // strings work too:
  // ZstdPackStr(text, dStr, 9) / ZstdUnpackStr(zStr, dStr)
end;
```

The trainer selects content by the frequency of 8-byte windows (1 KB epochs, the best material placed at the end of the dictionary) and derives the entropy tables from the histograms of compressing the samples.

## Format coverage

The decoder accepts everything a standard zstd encoder produces: raw / RLE / compressed blocks; Huffman literals (1 and 4 streams, direct-nibble and FSE tree descriptions, treeless blocks); sequences in predefined / RLE / FSE / repeat modes; repeat offsets with the `literals_length = 0` shift rule; concatenated frames; skippable frames; the xxhash64 content checksum; frames with no declared size; and dictionaries (raw and structured) with dictionary-id enforcement.

The encoder uses the full toolbox: raw / RLE / Huffman literals (code lengths from package-merge, optimal under the 11-bit limit), sequence tables chosen per channel by cost (predefined / RLE / fresh FSE / repeat), treeless literals, repeat offsets, and dictionaries. Levels 1–9. Out of scope: the legacy formats (zstd v0.1–0.7, predating the finalized RFC).

## CLI

`zstd.lpr` is a small command-line front-end over the three units:

```
zstd -c [-1..-9] [-D dict] <input> [output]   compress (default level 6)
zstd -d [-D dict] <input> [output]            decompress
zstd -train [-s kb] <out.dict> <samples...>   train a dictionary (default 110 kb)
```

Behaviour, read straight from the code:

- **Output name** - when omitted, `-c` appends `SUFFIX` (`.zst`) to the input name and `-d` strips it (and requires it to be there).
- **Overwrite** - an existing output file prompts `overwrite? [y/N]`; anything but `y`/`yes` aborts. Input and output may not be the same file.
- **Streaming** - files are processed in 1 MB chunks, so memory stays flat regardless of file size; a percentage ticks while it runs, and a summary (sizes, ratio, time) prints at the end.
- **Dictionaries** - `-D` loads a dictionary (raw bytes or a trained `.dict`) for both directions. `-train` accepts files, directories (walked recursively), and `*` / `?` globs; a single sample file is sliced into 4 KB pieces, and the file set is sorted so a directory and the matching glob train identical dictionaries.
- **Errors** - a corrupt or wrong-dictionary stream on `-d` prints a specific message (e.g. *not a zstandard stream*, *content checksum mismatch*, *stream requires an external dictionary*) and removes the partial output. Exit code is non-zero on any error.

## Building

Build the command-line tool:

```
fpc -O3 zstd.lpr
```

Or open `zstd.lpi` in the IDE and compile.

Requires a compiler with the `unleashed` mode.

## License

MIT, see [LICENSE](LICENSE). Free to use and modify; when you redistribute the sources, keep the author attribution: @fibodevy / https://github.com/fibodevy/zstd-fpc
