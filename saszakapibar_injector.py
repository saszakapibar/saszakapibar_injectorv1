import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import psutil
import ctypes
from PIL import Image, ImageTk 


LANGUAGES = {
    "PL": {
        "title": "Saszakapibar Injector v2.3",
        "select_proc": "Wybierz proces z listy:",
        "refresh": "Odśwież listę",
        "inject_btn": "INIEKTUJ PLIK DLL",
        "err_no_proc": "Najpierw wybierz proces z listy!",
        "err_empty_row": "Wybrany wiersz jest pusty. Kliknij na proces.",
        "err_data": "Nie można odczytać danych procesu.",
        "select_dll": "Wybierz plik DLL do iniekcji",
        "err_admin": "Uruchom jako Administrator! Inaczej Windows zablokuje dostęp.",
        "success": "Plik DLL został pomyślnie wstrzyknięty!",
        "method_lbl": "Metoda iniekcji:",
        "lang_lbl": "Język / Язык / Language:",
        "search_lbl": "Szukaj procesu:"
    },
    "RU": {
        "title": "Saszakapibar Injector v2.3",
        "select_proc": "Выберите процесс из списка:",
        "refresh": "Обновить список",
        "inject_btn": "ИНЖЕКТИРОВАТЬ DLL",
        "err_no_proc": "Сначала выберите процесс из списка!",
        "err_empty_row": "Wybrany wiersz jest pusty. Кликните на процесс.",
        "err_data": "Не удалось прочитать данные процесса.",
        "select_dll": "Выберите DLL file для инжекта",
        "err_admin": "Запустите от имени Администратора! Иначе Windows заблокирует доступ.",
        "success": "DLL файл успешно внедрен!",
        "method_lbl": "Метод инжекта:",
        "lang_lbl": "Язык:",
        "search_lbl": "Поиск процесса:"
    },
    "EN": {
        "title": "Saszakapibar Injector v2.3",
        "select_proc": "Select a process from the list:",
        "refresh": "Refresh list",
        "inject_btn": "INJECT DLL FILE",
        "err_no_proc": "Please select a process first!",
        "err_empty_row": "Selected row is empty. Click on a process.",
        "err_data": "Could not read process data.",
        "select_dll": "Select DLL file for injection",
        "err_admin": "Run as Administrator! Otherwise Windows will block access.",
        "success": "DLL file successfully injected!",
        "method_lbl": "Injection Method:",
        "lang_lbl": "Language:",
        "search_lbl": "Search process:"
    }
}


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]

class CONTEXT64(ctypes.Structure):
    _align_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("Header", M128A * 2), ("Legacy", M128A * 8),
        ("Xmm0", M128A), ("Xmm1", M128A), ("Xmm2", M128A), ("Xmm3", M128A),
        ("Xmm4", M128A), ("Xmm5", M128A), ("Xmm6", M128A), ("Xmm7", M128A),
        ("Xmm8", M128A), ("Xmm9", M128A), ("Xmm10", M128A), ("Xmm11", M128A),
        ("Xmm12", M128A), ("Xmm13", M128A), ("Xmm14", M128A), ("Xmm15", M128A),
        ("VectorRegister", M128A * 26), ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64), ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64)
    ]

kernel32 = ctypes.windll.kernel32
PROCESS_ALL_ACCESS = 0x001F0FFF
THREAD_ALL_ACCESS = 0x001F03FF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_long, ctypes.c_ulong]
kernel32.OpenProcess.restype = ctypes.c_void_p

kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.c_long

kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
kernel32.GetModuleHandleA.restype = ctypes.c_void_p

kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.CreateRemoteThread.restype = ctypes.c_void_p

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_long

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

class SaszakapibarInjector(tk.Tk):
    def __init__(self):
        super().__init__()
        self.current_lang = "PL"  
        self.title(LANGUAGES[self.current_lang]["title"])
        self.geometry("650x670")  
        self.resizable(False, False)
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.all_processes = []
        
        self.create_widgets()
        self.refresh_processes()
        
        if not is_admin():
            messagebox.showwarning("UAC", LANGUAGES[self.current_lang]["err_admin"])

    def create_widgets(self):
        lang_frame = ttk.Frame(self, padding=5)
        lang_frame.pack(fill=tk.X)
        
        self.lang_lbl = ttk.Label(lang_frame, text=LANGUAGES[self.current_lang]["lang_lbl"])
        self.lang_lbl.pack(side=tk.LEFT, padx=5)
        
        self.lang_combo = ttk.Combobox(lang_frame, values=["PL", "RU", "EN"], width=5, state="readonly")
        self.lang_combo.set(self.current_lang)
        self.lang_combo.pack(side=tk.LEFT, padx=5)
        self.lang_combo.bind("<<ComboboxSelected>>", self.change_language)

        
        self.image_path = r"C:\Users\nikol\AppData\Local\Programs\Python\Python313\FGH_shaXwAQOUid.png"
        if os.path.exists(self.image_path):
            try:
                img = Image.open(self.image_path)
                try:
                    resample_method = Image.Resampling.LANCZOS
                except AttributeError:
                    resample_method = Image.ANTIALIAS
                    
                img = img.resize((630, 130), resample_method)
                self.bg_image = ImageTk.PhotoImage(img)
                
                self.photo_label = tk.Label(self, image=self.bg_image)
                self.photo_label.pack(fill=tk.X, padx=10, pady=5)
            except Exception as e:
                print(f"[BŁĄD ŁADOWANIA OBRAZKA]: {e}")
        else:
            print(f"[INFORMACJA]: Nie znaleziono obrazka pod ścieżką: {self.image_path}")

     
        search_frame = ttk.Frame(self, padding=10)
        search_frame.pack(fill=tk.X)
        
        self.search_lbl = ttk.Label(search_frame, text=LANGUAGES[self.current_lang]["search_lbl"], font=("Arial", 10, "bold"))
        self.search_lbl.pack(side=tk.LEFT, padx=5)
        
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_processes)
        
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        proc_frame = ttk.Frame(self, padding=10)
        proc_frame.pack(fill=tk.X)
        
        self.select_proc_lbl = ttk.Label(proc_frame, text=LANGUAGES[self.current_lang]["select_proc"], font=("Arial", 10, "bold"))
        self.select_proc_lbl.pack(side=tk.LEFT)
        
        self.refresh_btn = ttk.Button(proc_frame, text=LANGUAGES[self.current_lang]["refresh"], command=self.refresh_processes)
        self.refresh_btn.pack(side=tk.RIGHT)

       
        tree_frame = ttk.Frame(self, padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("pid", "name", "status")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Nazwa / Имя / Name")
        self.tree.heading("status", text="Status")
        
        self.tree.column("pid", width=80, anchor=tk.CENTER)
        self.tree.column("name", width=380, anchor=tk.W)
        self.tree.column("status", width=120, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        bottom_frame = ttk.Frame(self, padding=15)
        bottom_frame.pack(fill=tk.X)
        
        self.method_lbl = ttk.Label(bottom_frame, text=LANGUAGES[self.current_lang]["method_lbl"])
        self.method_lbl.pack(side=tk.LEFT, padx=5)
        
        self.method_combo = ttk.Combobox(bottom_frame, values=["Standard", "Thread Hijacking", "Manual Map"], state="readonly", width=18)
        self.method_combo.set("Standard")
        self.method_combo.pack(side=tk.LEFT, padx=5)
        
        self.inject_btn = ttk.Button(bottom_frame, text=LANGUAGES[self.current_lang]["inject_btn"], command=self.inject_logic, width=25)
        self.inject_btn.pack(side=tk.RIGHT, padx=5)

    def change_language(self, event=None):
        self.current_lang = self.lang_combo.get()
        self.title(LANGUAGES[self.current_lang]["title"])
        self.lang_lbl.config(text=LANGUAGES[self.current_lang]["lang_lbl"])
        self.search_lbl.config(text=LANGUAGES[self.current_lang]["search_lbl"])
        self.select_proc_lbl.config(text=LANGUAGES[self.current_lang]["select_proc"])
        self.refresh_btn.config(text=LANGUAGES[self.current_lang]["refresh"])
        self.method_lbl.config(text=LANGUAGES[self.current_lang]["method_lbl"])
        self.inject_btn.config(text=LANGUAGES[self.current_lang]["inject_btn"])
    def refresh_processes(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.all_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                if proc.info['status'] == psutil.STATUS_RUNNING:
                    self.all_processes.append((proc.info['pid'], proc.info['name']))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.filter_processes()

    def filter_processes(self, *args):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        search_query = self.search_var.get().lower()
        
        for pid, name in self.all_processes:
            if search_query in name.lower():
                self.tree.insert("", tk.END, values=(pid, name, "OK"))

    def inject_logic(self):
        lang = self.current_lang
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Błąd / Error", LANGUAGES[lang]["err_no_proc"])
            return

        try:
            item_id = selected[0]  
            item_data = self.tree.item(item_id)
            item_values = item_data.get('values', [])
            
            if not item_values or len(item_values) < 2:
                messagebox.showwarning("Błąd / Error", LANGUAGES[lang]["err_empty_row"])
                return
                
            pid = int(item_values[0])      
            proc_name = str(item_values[1])  
        except (IndexError, ValueError, KeyError, TypeError) as e:
            messagebox.showerror("Błąd / Error", f"{LANGUAGES[lang]['err_data']}\n{str(e)}")
            return

        dll_path = filedialog.askopenfilename(
            title=LANGUAGES[lang]["select_dll"],
            filetypes=[("Pliki DLL", "*.dll")]
        )
        if not dll_path: 
            return

        method = self.method_combo.get()
        
        if method == "Standard":
            self.method_standard(pid, dll_path, lang, proc_name)
        elif method == "Thread Hijacking":
            self.method_hijack(pid, dll_path, lang, proc_name)
        elif method == "Manual Map":
            self.method_manual_map(pid, dll_path, lang, proc_name)

    def method_standard(self, pid, dll_path, lang, proc_name):
        dll_bytes = dll_path.encode('utf-8') + b'\x00'
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            messagebox.showerror("WinAPI Error", f"OpenProcess failed. Code: {kernel32.GetLastError()}")
            return

        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            kernel32.CloseHandle(h_process)
            messagebox.showerror("WinAPI Error", f"VirtualAllocEx failed. Code: {kernel32.GetLastError()}")
            return

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(written))
        
        h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
        load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
        
       
        tid = ctypes.c_ulong(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_lib, remote_mem, 0, ctypes.byref(tid))
        
        if h_thread:
            kernel32.CloseHandle(h_thread)
            messagebox.showinfo("Success", f"{LANGUAGES[lang]['success']}\nTarget: {proc_name} (PID: {pid})")
        else:
            messagebox.showerror("WinAPI Error", f"CreateRemoteThread failed. Code: {kernel32.GetLastError()}")
            
        kernel32.CloseHandle(h_process)

    def method_hijack(self, pid, dll_path, lang, proc_name):
        dll_bytes = dll_path.encode('utf-8') + b'\x00'
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            messagebox.showerror("WinAPI Error", f"OpenProcess failed. Code: {kernel32.GetLastError()}")
            return

        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(written))

        h_thread = None
        for thread in psutil.Process(pid).threads():
            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
            if h_thread:
                break

        if not h_thread:
            kernel32.CloseHandle(h_process)
            messagebox.showerror("Error", "Could not hijack thread. Active thread not found.")
            return

        kernel32.SuspendThread(h_thread)
        ctx = CONTEXT64()
        ctx.ContextFlags = 0x00100000 | 0x00000002  
        
        if kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
            h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
            load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
            
            ctx.Rip = load_lib  
            ctx.Rcx = remote_mem  
            
            kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
            messagebox.showinfo("Success", f"{LANGUAGES[lang]['success']} (Thread Hijacked)\nTarget: {proc_name}")
        else:
            messagebox.showerror("WinAPI Error", f"GetThreadContext failed. Code: {kernel32.GetLastError()}")

        kernel32.ResumeThread(h_thread)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)

    def method_manual_map(self, pid, dll_path, lang, proc_name):
        try:
            with open(dll_path, "rb") as f:
                dll_data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read DLL file: {str(e)}")
            return

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            messagebox.showerror("WinAPI Error", "OpenProcess failed.")
            return

        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_data), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if remote_mem:
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(h_process, remote_mem, dll_data, len(dll_data), ctypes.byref(written))
            
            h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
            load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
            
           
            tid = ctypes.c_ulong(0)
            kernel32.CreateRemoteThread(h_process, None, 0, load_lib, remote_mem, 0, ctypes.byref(tid))
            
            messagebox.showinfo("Success", f"{LANGUAGES[lang]['success']} (Manual Map Mode)\nTarget: {proc_name}")
        else:
            messagebox.showerror("WinAPI Error", "VirtualAllocEx allocation failed.")
            
        kernel32.CloseHandle(h_process)


if __name__ == "__main__":
    app = SaszakapibarInjector()
    app.mainloop()

  
