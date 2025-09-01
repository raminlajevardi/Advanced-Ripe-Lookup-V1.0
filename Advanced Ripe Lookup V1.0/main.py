import tkinter as tk
from gui.main_window import AdvancedRIPEIPLookup

def main():
    """نقطه‌ی شروع برنامه و ایجاد پنجره‌ی Tkinter."""
    root = tk.Tk()
    app = AdvancedRIPEIPLookup(root)
    root.mainloop()

if __name__ == "__main__":
    main()
