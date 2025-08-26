import os
import re
from pathlib import Path
import ida_hexrays
import idaapi
import ida_kernwin

def collect_objc_methods():
    objc_methods = {}
    for i in range(idaapi.get_nlist_size()):
        name = idaapi.get_nlist_name(i)
        ea = idaapi.get_nlist_ea(i)
        # 只收集 -[ClassName MethodName] 这种符号
        m = re.match(r'[\-\+]\[([A-Za-z0-9_]+) ([^\]]+)\]', name)
        if m:
            class_name = m.group(1)
            method_name = m.group(2)
            if class_name not in objc_methods:
                objc_methods[class_name] = []
            objc_methods[class_name].append({
                'name': name,
                'ea': ea,
                'method_name': method_name
            })
    return objc_methods

def find_related_symbols(code):
    # 匹配 __xxx、_xxx、block_invoke、helper、descriptor 等符号名
    return set(re.findall(r'\b(__[A-Za-z0-9_]+|_[A-Za-z0-9_]+|[A-Za-z0-9_]+_block_invoke[0-9]*|[A-Za-z0-9_]+_helper[0-9]*|[A-Za-z0-9_]+_descriptor[0-9]*)\b', code))

def get_symbol_ea(symbol_name):
    for i in range(idaapi.get_nlist_size()):
        if idaapi.get_nlist_name(i) == symbol_name:
            return idaapi.get_nlist_ea(i)
    return None

def find_class_related_symbols(class_name):
    related = []
    keywords = ["block_invoke", "helper", "descriptor"]
    for i in range(idaapi.get_nlist_size()):
        name = idaapi.get_nlist_name(i)
        ea = idaapi.get_nlist_ea(i)
        if class_name in name and any(k in name for k in keywords):
            related.append((name, ea))
    return related

def export_objc_methods(output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    objc_methods = collect_objc_methods()
    total_classes = 0
    total_methods = 0
    total_related = 0
    for class_name, methods in objc_methods.items():
        total_classes += 1
        lines = [f'@implementation {class_name}\n']
        for m in methods:
            try:
                decompiled = ida_hexrays.decompile(m['ea'])
                code = str(decompiled) if decompiled else ''
                if code.strip():
                    lines.append(f"// {m['name']}\n{code}\n")
                    total_methods += 1
            except Exception as exc:
                lines.append(f"// {m['name']}\n// [ERROR] {exc}\n")
        # 导出所有符号表中与类相关的 block/invoke/helper/descriptor
        related_syms = find_class_related_symbols(class_name)
        for sym_name, ea in related_syms:
            try:
                decompiled = ida_hexrays.decompile(ea)
                code = str(decompiled) if decompiled else ''
                if code.strip():
                    lines.append(f"// 关联符号: {sym_name}\n{code}\n")
                    total_related += 1
            except Exception as exc:
                lines.append(f"// 关联符号: {sym_name}\n// [ERROR] {exc}\n")
        lines.append('\n@end\n')
        file_path = output_dir / f"{class_name}.m"
        file_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f"Objective-C 导出完成，总计导出 {total_classes} 个类，{total_methods} 个方法，{total_related} 个关联符号。")

class ObjCExportPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Export Objective-C methods by symbol table"
    help = comment
    wanted_name = "Export ObjC .m files (symbol table)"
    wanted_hotkey = "Ctrl-Shift-O"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        try:
            ida_kernwin.show_wait_box("HIDECANCEL\nExporting ObjC .m files...")
            binary_name = idaapi.get_root_filename()
            output_dir_hint = f"{binary_name}_objc_exported"
            output_path = ida_kernwin.ask_file(True, output_dir_hint, "Select output directory")
            if output_path:
                export_objc_methods(output_path)
        except Exception as e:
            ida_kernwin.warning(f"Failed to export ObjC files: {e}")
        finally:
            ida_kernwin.hide_wait_box()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return ObjCExportPlugin()
