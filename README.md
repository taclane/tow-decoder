# The Outer Worlds conversation decoder

The Outer Worlds (1) stores each conversation's dialogue graph as an opaque binary blob inside its exported UAsset JSON with no public schema. This script decodes that blob into plain JSON. It was built with the aid of Ghidra, and checked against all 961 conversation files that ship with the latest edition of the game. Every one decodes cleanly.

The byte format itself, and a few details that were never fully confirmed, are documented as comments in the script, next to the code that handles them.

## Use

```
python3 tow_decoder.py CONVERSATION.json                   # decoded JSON to stdout
python3 tow_decoder.py CONVERSATION.json -o out.json       # decoded JSON to a file
python3 tow_decoder.py dump_dir/ -o decoded_dir/           # batch: mirrors dump_dir's tree
```

Input files are UAsset JSON exports of `*.conversationbundle` assets (e.g. from FModel), each holding a `SerializedConversationData` byte array

Run with `-h` for the full option list. No dependencies beyond Python 3.9+.