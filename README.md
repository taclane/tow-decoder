<center>"What the eff is this? Is this.... Binary? I can't effing read Binary!"<br>
&nbsp;&nbsp;&nbsp;&nbsp;- Vicar Maximillian DeSoto</center>

# The Outer Worlds conversation decoder

The Outer Worlds stores each conversation file as a binary blob inside the exported UAsset JSON with no public schema. This script decodes that blob into plain JSON. It was built with the aid of Ghidra, and checked against every conversation file that shiped with the latest edition of the game. 

Every OEI Tools .conversationbundle found in TOW decodes cleanly, and produces output consistent with other Obsidian titles.

## Usage

```
python3 tow_decoder.py CONVERSATION.json                   # decoded JSON to stdout
python3 tow_decoder.py CONVERSATION.json -o out.json       # decoded JSON to a file
python3 tow_decoder.py dump_dir/ -o decoded_dir/           # batch: mirrors dump_dir's tree
```

Input files are UAsset JSON exports of `*.conversationbundle` assets (e.g. from FModel), each holding a `SerializedConversationData` byte array

Run with `-h` for the full option list. No dependencies beyond Python 3.9+.

## Why?

Well, um.  That's a great question. 

Maybe it would be better to figure out why they were even packed this way in the first place.
