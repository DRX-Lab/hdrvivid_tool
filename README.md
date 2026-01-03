# **hdrvivid_tool**

`hdrvivid_tool` is a command-line tool for working with **HDR Vivid** metadata in **HEVC Annex-B** bitstreams.

It allows you to:

* Inspect HEVC files for HDR Vivid metadata
* Extract HDR Vivid metadata to a single BIN file
* Remove HDR Vivid metadata from a video
* Inject HDR Vivid metadata from a BIN into a video
* Plot HDR Vivid metadata from a BIN into a PNG image

---

## **Requirements**

* Python **3.9+**
* For `plot` only:

  ```console
  pip install matplotlib
  ```

---

## **Basic Usage**

```console
hdrvivid_tool <command> [options]
```

To see help for a command:

```console
hdrvivid_tool <command> --help
```

---

## **Commands**

### **info**

Validate and analyze an HEVC stream.
(Progress bar only.)

```console
python hdrvivid_tool.py info -i input.hevc
```

---

### **extract**

Extract HDR Vivid metadata from an HEVC file into a **single BIN**.

```console
python hdrvivid_tool.py extract -i input.hevc -o metadata.bin
```

---

### **remove**

Remove HDR Vivid metadata from an HEVC file.

```console
python hdrvivid_tool.py remove -i input.hevc -o output_no_vivid.hevc
```

---

### **inject**

Inject or replace HDR Vivid metadata from a BIN into an HEVC file.

Behavior:

* Verifies frame order using AUD NAL units
* If BIN length ≠ video frame count:

  * Short BIN → metadata is duplicated to match
  * Long BIN → metadata is truncated

Output:

* Informational prints (dovi_tool-style)
* **Exactly two progress bars**

```console
python hdrvivid_tool.py inject -i input.hevc --bin metadata.bin -o output_injected.hevc
```

---

### **plot**

Generate a PNG plot from a BIN file (**no HEVC input required**).
* Title: **HDR Vivid Plot**
* Uses BIN filename in the overlay

```console
python hdrvivid_tool.py plot -i metadata.bin -o plot.png
```

---
