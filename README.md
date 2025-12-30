<p align="center">
  <img alt="zenella" src="media/zenellaLogo.png" width="160">
</p>

# AMD Zen 5 Microcode Update Reversing (call it `Zenella`) (Binary Ninja Plugin)

This plugin adds a small set of **Binary Ninja menu commands** that help you quickly apply a known data-structure layout to AMD Zen 5 microcode `.bin` blobs (typically `0x3820` bytes). Once applied, the Binary Ninja “Linear” view becomes navigable: header fields are parsed, the random blocks are labeled, and the structured µcode region is represented as an array of 4-byte micro-ops.

The plugin is intentionally lightweight: it does **not** disassemble microcode. It only maps bytes into structs and adds sparse comments for quick triage.

## Requirements

- **Binary Ninja** (Desktop) with Python scripting enabled (standard)
- **Python**: use the Python runtime embedded in Binary Ninja (you do not need a system Python for the plugin itself)

## Installation / Setup

### 1) Locate the plugin directory
In Binary Ninja:
- `Plugins` -> `Open Plugin Folder...`<br>
  Example: `/Users/ercihan/Library/Application\ Support/Binary\ Ninja/plugins`

### 2) Copy the plugin file
Place the plugin into the above found folder path and restart Binary Ninja.

### 3) Check plugins
As soon as the Binary Ninja has been restarted you should see a menu like this:<br>
![pluginOverview](media/pluginOverview.png)

## Type Setup (what the plugin expects)

Most reliable workflow:
1) In Binary Ninja, open the microcode `.bin`
2) Go to `Types` -> `Create Types from C Source…`
3) Paste the C struct definitions (header/random blocks/micro-op struct/region struct)

The plugin then calls `bv.get_type_by_name(...)` and applies these types at the correct offsets.

## Menu Commands and What They Do

The plugin typically registers commands like these (names depend on your exact plugin version):

### 1) **Apply layout at file start (0x0)**
**What it does**
- Creates types (e.g. `amd_mc_header`, `amd_mc_random_blocks`, `amd_ucode_region`) for navigation
- Applies the header struct at **0x0000**
- Applies the random blocks struct at **0x0020**
- Applies the structured µcode region at **0x0320**

**When to use**
- Use this for normal microcode blobs where the file is mapped starting at offset `0`.

### 2) **Apply layout at cursor**
**What it does**
- Same as "Apply layout at file start", but uses the current cursor address as the base.
- Useful if the microcode blob is embedded inside a larger container and you navigated to the blob’s start.

**Notes**
- If there are not enough bytes remaining for a full `0x3820` blob, a well-behaved plugin will either:
  1) apply a partial layout or
  2) warn that the layout is partial

## Common Workflow
1) Drop plugin into the `plugins/` folder
2) Restart Binary Ninja
3) Open a microcode `.bin`
4) Run `Apply layout at file start (0x0)`

## Common workflow in action (video)
<video controls width="720">
  <source src="media/workflowExample.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>
