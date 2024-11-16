from tkinter.ttk import Frame

from ttkthemes import ThemedTk
from tkinter import ttk

class ClientGUI:
    def __init__(self):
        self.root = ThemedTk(theme="arc")
        self.button_frame: ttk.Frame = None
        self.key_menu_button: ttk.Button = None
        self.connection_menu_button: ttk.Button = None
        self.key_frame: ttk.Frame = None
        self.connection_frame: ttk.Frame = None
        self.build_ui()

    def build_ui(self):
        self.root.title("TPM-CPKS Client")
        self.root.geometry("1200x700+100+200")
        self.root.resizable(False, False)

        # Button frame
        self.button_frame = ttk.Frame(self.root)
        self.button_frame.pack(fill="x", side="top")

        # Buttons
        self.key_menu_button = ttk.Button(self.button_frame, text="Key", command=self.key_menu_button_command)
        self.key_menu_button.pack(side="left", fill="x", expand=True)
        self.key_menu_button.state(["disabled"])
        self.connection_menu_button = ttk.Button(self.button_frame, text="Connection",
                                                 command=self.connection_menu_button_command)
        self.connection_menu_button.pack(side="right", fill="x", expand=True)

        # Menu frame container
        self.frame_container = ttk.Frame(self.root)
        self.frame_container.pack(fill="both", expand=True)

        # Key Frame
        self.key_frame = ttk.Frame(self.frame_container)
        self.key_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.key_frame, text="Key Frame").grid(row=0, column=0, sticky="nsew")

        # Connection Frame
        self.connection_frame = ttk.Frame(self.frame_container)
        self.connection_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.connection_frame, text="Connection Frame").grid(row=0, column=0, sticky="nsew")

        self.key_frame.tkraise()


    def key_menu_button_command(self):
        self.key_menu_button.state(["disabled"])
        self.connection_menu_button.state(["!disabled"])
        self.key_frame.tkraise()

    def connection_menu_button_command(self):
        self.key_menu_button.state(["!disabled"])
        self.connection_menu_button.state(["disabled"])
        self.connection_frame.tkraise()

    def run(self):
        self.root.mainloop()


def main():
    cgui = ClientGUI()
    cgui.run()


if __name__ == "__main__":
    main()