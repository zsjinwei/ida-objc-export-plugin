import struct
from pathlib import Path
from typing import Any

import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_segment
import idaapi

STRUCTS = {
    "class_t": struct.Struct("<QQQQQ"),
    "class_ro_t": struct.Struct("<IIIIQQQQQQQ"),
    "method_t": struct.Struct("<iii"),
}


def get_string(ea: int) -> str | None:
    if result := ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C):
        return result.decode()
    if ptr := ida_bytes.get_qword(ea):
        if result := ida_bytes.get_strlit_contents(ptr, -1, ida_nalt.STRTYPE_C):
            return result.decode()
    return None


def extract_method(method_ea: int) -> dict | None:
    data = ida_bytes.get_bytes(method_ea, STRUCTS["method_t"].size)
    name_offset, types_offset, imp_offset = STRUCTS["method_t"].unpack(data)
    method_base = method_ea

    if name := get_string(method_base + name_offset):
        imp_ea = method_base + imp_offset
        decompiled = str(ida_hexrays.decompile(imp_ea))

        return {
            "name": name,
            "type": get_string(method_base + types_offset),
            "implementation": imp_ea,
            "decompiled": decompiled,
        }
    return None


def extract_methods(methods_ea: int) -> list:
    methods = []
    if not methods_ea:
        return methods

    count = ida_bytes.get_dword(methods_ea + 4)
    first_method = methods_ea + 8

    for i in range(count):
        if method := extract_method(first_method + i * 12):
            methods.append(method)
    return methods


def extract_class(class_ea: int) -> dict | None:
    data = ida_bytes.get_bytes(class_ea, STRUCTS["class_t"].size)
    isa, superclass, _, _, info = STRUCTS["class_t"].unpack(data)

    info = (info >> 3) << 3
    data = ida_bytes.get_bytes(info, STRUCTS["class_ro_t"].size)
    class_ro = STRUCTS["class_ro_t"].unpack(data)

    if not (class_name := get_string(class_ro[5])):
        return None

    meta_data = ida_bytes.get_bytes(isa, STRUCTS["class_t"].size)
    _, _, _, _, meta_info = STRUCTS["class_t"].unpack(meta_data)
    meta_info = (meta_info >> 3) << 3
    meta_ro_data = ida_bytes.get_bytes(meta_info, STRUCTS["class_ro_t"].size)
    meta_ro = STRUCTS["class_ro_t"].unpack(meta_ro_data)

    return {
        "name": class_name,
        "address": class_ea,
        "superclass": superclass,
        "methods": extract_methods(class_ro[6]),
        "class_methods": extract_methods(meta_ro[6]),
    }

def extract_all_classes() -> dict:
    classes = {}
    if segment := ida_segment.get_segm_by_name("__objc_classlist"):
        last_shown = -1
        for ea in range(segment.start_ea, segment.end_ea, 8):
            progress = int((ea - segment.start_ea) * 100 / (segment.end_ea - segment.start_ea))
            if progress != last_shown:
                ida_kernwin.replace_wait_box(f"HIDECANCEL\nExtracting classes... ({progress}%)")
                last_shown = progress
            if class_ptr := ida_bytes.get_qword(ea):
                if class_info := extract_class(class_ptr):
                    classes[class_info["name"]] = class_info
    return classes

def generate_source_files(classes: dict, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    for class_name, info in classes.items():
        output = [f"@implementation {class_name}\n"]

        if info["class_methods"]:
            output.extend(m["decompiled"] for m in info["class_methods"])

        if info["methods"]:
            output.extend(m["decompiled"] for m in info["methods"])

        output.append("\n@end\n")
        (output_dir / f"{class_name}.m").write_text("\n".join(output))


class ObjCSourceExport(ida_idaapi.plugin_t):
    flags = 0
    comment = "Objc source export"
    help = comment
    wanted_name = "Export .m files"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self) -> int:
        if idaapi.IDA_SDK_VERSION < 900:
            ida_kernwin.warning("Objc Source Export is only tested on IDA 9")

        return ida_idaapi.PLUGIN_OK

    def run(self, _: Any) -> None:
        try:
            ida_kernwin.show_wait_box("HIDECANCEL\nGenerating .m files...")
            if not ida_hexrays.init_hexrays_plugin():
                return

            for_saving = True
            binary_name = ida_nalt.get_root_filename()
            output_file_dir_hint = f"{binary_name}_exported"
            if output_path := ida_kernwin.ask_file(for_saving, output_file_dir_hint, "Select output directory"):
                classes = extract_all_classes()
                generate_source_files(classes, Path(output_path))

        except Exception as e:
            ida_kernwin.warning(f"Failed to generate source files: {e}")
        finally:
            ida_kernwin.hide_wait_box()

    def term(self) -> None:
        pass


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:
    return ObjCSourceExport()
