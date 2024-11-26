from ttkthemes import ThemedTk
from tkinter import ttk
import tkinter as tk

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
        self.root.geometry("800x400+100+200")
        self.root.resizable(False, False)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

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
        self.frame_container.columnconfigure(0, weight=1)
        self.frame_container.rowconfigure(0, weight=1)

        # Key Frame
        self.key_frame = ttk.Frame(self.frame_container)
        self.key_frame.config(padding=[20,20,20,20])
        self.key_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.key_frame, text="Key Frame").grid(row=0, column=0, sticky="nsew")

        # Connection Frame
        self.connection_frame = ttk.Frame(self.frame_container, borderwidth=5, relief="solid")
        self.connection_frame.config(padding=[20,40,20,40])
        self.connection_frame.grid(row=0, column=0, sticky="nsew")
        self.connection_frame.columnconfigure(tuple(range(2)), weight=1, uniform="a")
        self.connection_settings_frame = ttk.Frame(self.connection_frame)
        self.connection_settings_frame.grid(row=0, column=0, sticky="")
        self.connection_actions_frame = ttk.Frame(self.connection_frame)
        self.connection_actions_frame.grid(row=0, column=1, sticky="")
        ttk.Label(self.connection_settings_frame, text="Host address: ").grid(row=0, column=0, sticky="w")
        self.host_entry = ttk.Entry(self.connection_settings_frame)
        self.host_entry.grid(row=1, column=0)
        # ttk.Label(self.connection_frame, text="Connection Frame").grid(row=0, column=0, sticky="nsew")
        # ttk.Entry(self.connection_frame).grid(row=1,column=0,sticky="")
        self.connect_button = ttk.Button(self.connection_actions_frame, text="Connect",
                                         command=self.connect_button_command, width=30)
        self.connect_button.grid(row=1, column=1, sticky="")
        self.send_key_button = ttk.Button(self.connection_actions_frame, text="Send Public Key",
                                          command=self.send_key_button, width=30)
        self.send_key_button.state(["disabled"])
        self.send_key_button.grid(row=2,column=1,sticky="")

        self.message_box = tk.Text(self.connection_actions_frame, height=5, width=40)
        self.message_box.config(state="disabled")
        self.message_box.grid(row=0,column=1, sticky="")

        self.key_frame.tkraise()

    def send_key_button(self):
        pass

    def connect_button_command(self):
        print("a")

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