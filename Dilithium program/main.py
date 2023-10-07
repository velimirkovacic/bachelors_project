from inspect import signature
from traceback import clear_frames
from turtle import bgcolor, left
from tkinter import *
import tkinter.ttk as ttk
import tkinter.font as font
import tkinter.messagebox as mbox
import dilithium
from ctypes import *


class App(Frame):
    
    # Variables that describe how many characters will be shown in the interface
    SHOWN_CHARS = 15
    SHOWN_CHARS_SIG = 25

    # Main cryptographic attributes 
    public_key = None
    private_key = None
    signature = None
    signature_length = None
    message = None
    encrypted_message = None
    encrypted_message_length = None
    decrypted_message = None

    # Widgets
    public_key_value = None
    private_key_value = None
    signature_value = None
    textbox_public_key = None
    textbox_private_key = None
    textbox_signature = None
    message_box = None
    digital_signature_label = None
    encrypted_message_value = None
    decrypted_message = None
    decrypted_message_label = None

    # Fonts
    title_font = None
    text_font = None
    button_font = None
    edit_button_font = None


    # Initialization
    def __init__(self):
        super().__init__()
        self.master.title("Crystals - Dilithium")
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.configure(background="white")

        # Font initialization
        self.title_font = font.Font(family='Calibri', size=22, weight='normal')
        self.text_font = font.Font(family='Calibri', size=12, weight='normal')
        self.button_font = font.Font(family='Calibri', size=12, weight='normal')
        self.edit_button_font = font.Font(family='Calibri', size=10, weight='normal')

        self.home_screen()


    # Function to convert array of type c_ubyte to string
    def ubyte_arr_to_hex_string(self, arr, arg):
        string = ""
        if(arg == 0):
            for i in arr:
                string += format(i, 'x') + " "
        else:
            for i in range(arg):
                string += format(arr[i], 'x') + " "
        return string


    # Function to destroy all widgets on screen
    def clear_screen(self):
        for widgets in self.winfo_children():
            widgets.destroy()


    # Function to check if int array is in hex
    def is_hex(self,s):
        for i in s:
            try:
                int(i, 16)
                if(int(i, 16) not in range(0, 256)):
                    return False
            except ValueError:
                return False
        return True


    # Function to convert byte array to c_ubyte array
    def bytes_to_ubyte_arr(self, bytes):
        arr = (c_ubyte * (len(bytes)))()
        for i in range(len(bytes)):
            arr[i] = c_ubyte(int(bytes[i], 16))
        return arr


    # Key generation and result display
    def generate_keys(self):
        self.public_key, self.private_key = dilithium.generate_keypair()
        self.public_key_value['text'] = self.ubyte_arr_to_hex_string(self.public_key, self.SHOWN_CHARS) + "..."
        self.private_key_value['text'] = self.ubyte_arr_to_hex_string(self.private_key, self.SHOWN_CHARS) + "..."
        self.encrypted_message = None
        self.encrypted_message_length = None
        if(self.encrypted_message_value != None):
            self.encrypted_message_value['text'] = ""

    # Signature generation and result display
    def generate_signature(self):
        if(self.private_key == None):
            return
        
        self.message = dilithium.string_to_ubyte_arr(self.message_box.get(1.0, END).strip('\n'))
        self.signature, self.signature_length = dilithium.generate_signature(self.message, self.private_key)
        self.signature_value['text'] = self.ubyte_arr_to_hex_string(self.signature, self.SHOWN_CHARS_SIG) + "..."
        

    # Message encryption and result display
    def encrypt_message(self):
        if(self.private_key == None):
            return
        
        self.message = dilithium.string_to_ubyte_arr(self.message_box.get(1.0, END).strip('\n'))
        self.encrypted_message, self.encrypted_message_length = dilithium.encrypt_message(self.message, self.private_key)
        self.encrypted_message_value['text'] = self.ubyte_arr_to_hex_string(self.encrypted_message, self.SHOWN_CHARS_SIG) + "..."
        

    # Message decryption and result display
    def decrypt_message(self):
        if(self.encrypted_message == None):
            return

        
        self.decrypted_message = dilithium.decrypt_message(self.encrypted_message, self.encrypted_message_length, self.public_key)
        self.decrypted_message_label['text'] = dilithium.ubyte_arr_to_string(self.decrypted_message)
 

    # Signature verification and result display
    def verify_signature(self):
        if(self.signature == None):
            return

        self.message = dilithium.string_to_ubyte_arr(self.message_box.get(1.0, END).strip('\n'))
        
        if(dilithium.verify_signature(self.signature, self.signature_length, self.message, self.public_key)):
            self.digital_signature_label['text'] = "Ispravan digitalni potpis"
            self.digital_signature_label['fg'] = "green" 
        else:
            self.digital_signature_label['text'] = "Neispravan digitalni potpis"
            self.digital_signature_label['fg'] = "red" 
        

    # Digital signature screen display
    def digital_sginature_screen(self):
        self.clear_screen()

        # Deleting cryptographic variables
        self.public_key = None
        self.private_key = None
        self.signature = None
        self.signature_length = None

        self.encrypted_message_value = None

        # Main frame configuration
        main_frame = Frame(self)
        main_frame.style=ttk.Style()
        main_frame.style.theme_use("default")
        main_frame.configure(background="white")
        main_frame.pack(fill=BOTH)

        title_label = Label(main_frame, text="DIGITALNI POTPIS", font=self.title_font, bg="white")
        title_label.pack(anchor="nw", fill=X, padx=20, pady=10)

        # Message frame configuration
        message_frame = Frame(main_frame)
        message_frame.style=ttk.Style()
        message_frame.style.theme_use("default")
        message_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        message_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        message_label = Label(message_frame, text="Poruka:", font=self.text_font, bg="white")
        message_label.pack(anchor="nw", side=LEFT, padx=10)

        self.message_box = Text(message_frame, height=4)
        self.message_box.pack(anchor="nw", fill=X)

        # Keys frame configuration
        keys_frame = Frame(main_frame)
        keys_frame.style=ttk.Style()
        keys_frame.style.theme_use("default")
        keys_frame.configure(background="white")
        keys_frame.pack(fill=X)

        # Generation button frame configuration
        generate_frame = Frame(keys_frame)
        generate_frame.style=ttk.Style()
        generate_frame.style.theme_use("default")
        generate_frame.configure(background="white")
        generate_frame.pack(fill=X, side=RIGHT, anchor="nw", padx=20, pady=10)

        generate_key_button = Button(generate_frame, text="Generiraj par ključeva", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.generate_keys)
        generate_key_button.pack(fill=X, padx=20, pady=10)

        generate_signature_button = Button(generate_frame, text="Generiraj digitalni potpis", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.generate_signature)
        generate_signature_button.pack(fill=X, padx=20, pady=10)

        # Public key frame configuration
        public_key_frame = Frame(keys_frame)
        public_key_frame.style=ttk.Style()
        public_key_frame.style.theme_use("default")
        public_key_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        public_key_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        public_key_label =  Label(public_key_frame, text="Javni ključ:", font=self.text_font, bg="white")
        self.public_key_value = Label(public_key_frame, text="", font=self.text_font, bg="white")
        public_key_edit = Button(public_key_frame, text="✎", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_public_key_window)
        public_key_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        public_key_edit.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.public_key_value.pack(fill=X, anchor="s", pady=10)

        # Private key frame configuration
        private_key_frame = Frame(keys_frame)
        private_key_frame.style=ttk.Style()
        private_key_frame.style.theme_use("default")
        private_key_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        private_key_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        private_key_label =  Label(private_key_frame, text="Privatni ključ:", font=self.text_font, bg="white")
        self.private_key_value = Label(private_key_frame, text="", font=self.text_font, bg="white")
        private_key_edit = Button(private_key_frame, text="✎", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_private_key_window)
        private_key_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        private_key_edit.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.private_key_value.pack(fill=X, anchor="s", pady=10)

        # Digital signature frame configuration
        digital_signature_frame = Frame(main_frame)
        digital_signature_frame.style=ttk.Style()
        digital_signature_frame.style.theme_use("default")
        digital_signature_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        digital_signature_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        digital_signature_label =  Label(digital_signature_frame, text="Digitalni potpis:", font=self.text_font, bg="white")
        self.signature_value = Label(digital_signature_frame, text="", font=self.text_font, bg="white")
        digital_signature_edit = Button(digital_signature_frame, text="✎", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_signature_window)
        digital_signature_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        digital_signature_edit.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.signature_value.pack(fill=X, anchor="s", pady=10)

        # Digital signature validity button configuration
        signature_validity_button = Button(main_frame, text="Provjeri digitalni potpis", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.verify_signature)
        signature_validity_button.pack(pady=(30, 10))

        # Digital signature validity frame configuration
        signature_validity_frame = Frame(main_frame)
        signature_validity_frame.style=ttk.Style()
        signature_validity_frame.style.theme_use("default")
        signature_validity_frame.configure(background="white", highlightbackground="black", highlightthickness=1)

        self.digital_signature_label =  Label(signature_validity_frame, text="", font=self.text_font, fg="green", bg="white", pady=10)
        self.digital_signature_label.pack(fill=X)

        signature_validity_frame.pack(fill=X, anchor="nw", padx=20, pady=10)

        # Return button configuration
        return_button = Button(main_frame, text="Natrag", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.home_screen)
        return_button.pack(side=RIGHT, padx=20, pady=10)
    

    # Encryption screen display
    def encryption_screen(self):
        self.clear_screen()

        # Deleting cryptographic variables
        self.public_key = None
        self.private_key = None
        self.signature = None
        self.signature_length = None
        self.encrypted_message = None
        self.encrypted_message_length = None
        self.decrypted_message = None

        # Main frame configuration
        main_frame = Frame(self)
        main_frame.style=ttk.Style()
        main_frame.style.theme_use("default")
        main_frame.configure(background="white")
        main_frame.pack(fill=BOTH)

        title_label = Label(main_frame, text="ENKRIPCIJA", font=self.title_font, bg="white")
        title_label.pack(anchor="nw", fill=X, padx=20, pady=10)

        # Message frame configuration
        message_frame = Frame(main_frame)
        message_frame.style=ttk.Style()
        message_frame.style.theme_use("default")
        message_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        message_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        message_label = Label(message_frame, text="Poruka:", font=self.text_font, bg="white")
        message_label.pack(anchor="nw", side=LEFT, padx=10)

        self.message_box = Text(message_frame, height=4)
        self.message_box.pack(anchor="nw", fill=X)

        # Keys frame configuration
        keys_frame = Frame(main_frame)
        keys_frame.style=ttk.Style()
        keys_frame.style.theme_use("default")
        keys_frame.configure(background="white")
        keys_frame.pack(fill=X)

        # Generation button frame configuration
        generate_frame = Frame(keys_frame)
        generate_frame.style=ttk.Style()
        generate_frame.style.theme_use("default")
        generate_frame.configure(background="white")
        generate_frame.pack(fill=X, side=RIGHT, anchor="nw", padx=20, pady=10)

        generate_key_button = Button(generate_frame, text="Generiraj par ključeva", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.generate_keys)
        generate_key_button.pack(fill=X, padx=20, pady=10)

        encrypt_message_button = Button(generate_frame, text="Kriptiraj poruku", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.encrypt_message)
        encrypt_message_button.pack(fill=X, padx=20, pady=10)

        # Public key frame configuration
        public_key_frame = Frame(keys_frame)
        public_key_frame.style=ttk.Style()
        public_key_frame.style.theme_use("default")
        public_key_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        public_key_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        public_key_label =  Label(public_key_frame, text="Javni ključ:", font=self.text_font, bg="white")
        self.public_key_value = Label(public_key_frame, text="", font=self.text_font, bg="white")
        #public_key_edit = Button(public_key_frame, text="✎", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_public_key_window)
        public_key_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        #public_key_edit.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.public_key_value.pack(fill=X, anchor="s", pady=10)

        # Private key frame configuration
        private_key_frame = Frame(keys_frame)
        private_key_frame.style=ttk.Style()
        private_key_frame.style.theme_use("default")
        private_key_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        private_key_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        private_key_label =  Label(private_key_frame, text="Privatni ključ:", font=self.text_font, bg="white")
        self.private_key_value = Label(private_key_frame, text="", font=self.text_font, bg="white")
        #private_key_edit = Button(private_key_frame, text="✎", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_private_key_window)
        private_key_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        #private_key_edit.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.private_key_value.pack(fill=X, anchor="s", pady=10)

        # Encrypted message frame configuration
        encrypted_message_frame = Frame(main_frame)
        encrypted_message_frame.style=ttk.Style()
        encrypted_message_frame.style.theme_use("default")
        encrypted_message_frame.configure(background="white", highlightbackground="black", highlightthickness=1)
        encrypted_message_frame.pack(fill=X,anchor="nw", padx=20, pady=10)

        encrypted_message_label =  Label(encrypted_message_frame, text="Kriptirana poruka:", font=self.text_font, bg="white")
        self.encrypted_message_value = Label(encrypted_message_frame, text="", font=self.text_font, bg="white")
        encrypted_message_view = Button(encrypted_message_frame, text="?", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.edit_button_font, bg="#f5f5f5", command=self.textbox_view_encrypted_message)
        encrypted_message_label.pack(side=LEFT, anchor="nw", padx=10, pady=10)
        encrypted_message_view.pack(side=RIGHT, anchor="ne", pady=10, padx=10)
        self.encrypted_message_value.pack(fill=X, anchor="s", pady=10)

        # Message decription button configuration
        decrypt_message_button = Button(main_frame, text="Dekriptiraj poruku", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.decrypt_message)
        decrypt_message_button.pack(pady=(30, 10))

        # Message decription validity frame configuration
        decrypted_message_frame = Frame(main_frame)
        decrypted_message_frame.style=ttk.Style()
        decrypted_message_frame.style.theme_use("default")
        decrypted_message_frame.configure(background="white", highlightbackground="black", highlightthickness=1)

        self.decrypted_message_label =  Label(decrypted_message_frame, text="", font=self.text_font, fg="black", bg="white", pady=10)
        self.decrypted_message_label.pack(fill=X)

        decrypted_message_frame.pack(fill=X, anchor="nw", padx=20, pady=10)

        # Return button configuration
        return_button = Button(main_frame, text="Natrag", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.home_screen)
        return_button.pack(side=RIGHT, padx=20, pady=10)

    
    # Function to check and save edited public key value
    def save_public_key_edit(self):
        bytes = self.textbox_public_key.get(1.0, END).strip().split(' ')
        if(len(bytes) != dilithium.PUBLIC_BYTES or not self.is_hex(bytes)):          
            mbox.showwarning(title="Upozorenje", message="Netočan unos!")
        else:
            mbox.showinfo(title="Obavijest", message="Promjene spremljene")
            self.public_key = self.bytes_to_ubyte_arr(bytes)
            self.public_key_value['text'] = self.ubyte_arr_to_hex_string(self.public_key, self.SHOWN_CHARS) + "..."
    
    
    # Function to check and save edited private key value
    def save_private_key_edit(self):
        bytes = self.textbox_private_key.get(1.0, END).strip().split(' ')
        if(len(bytes) != dilithium.PRIVATE_BYTES or not self.is_hex(bytes)):          
            mbox.showwarning(title="Upozorenje", message="Netočan unos!")
        else:
            mbox.showinfo(title="Obavijest", message="Promjene spremljene")
            self.private_key = self.bytes_to_ubyte_arr(bytes)
            self.private_key_value['text'] = self.ubyte_arr_to_hex_string(self.private_key, self.SHOWN_CHARS) + "..."


    # Function to check and save edited digital signature value
    def save_signature_edit(self):
        bytes = self.textbox_signature.get(1.0, END).strip().split(' ')
        if(len(bytes) != self.signature_length.value or not self.is_hex(bytes)):   
            mbox.showwarning(title="Upozorenje", message="Netočan unos!")
        else:
            mbox.showinfo(title="Obavijest", message="Promjene spremljene")
            self.signature = self.bytes_to_ubyte_arr(bytes)
            self.signature_value['text'] = self.ubyte_arr_to_hex_string(self.signature, self.SHOWN_CHARS_SIG) + "..."

    # Function to check encrypted message value
    def textbox_view_encrypted_message(self):
        if(self.encrypted_message == None):
            return
        
        # Popup window configuration
        popup = Toplevel(self)
        popup.style = ttk.Style()
        popup.style.theme_use("default")
        popup.configure(background="white")
        popup.title("Pregled kriptirane poruke")
        popup.geometry("700x520+300+150")
        
        Label(popup, text = "KRIPTIRANA PORUKA", font=self.text_font, bg="white").pack(pady=(10, 5))
        
        # Text frame configuration
        text_frame = Frame(popup)
        text_frame.style=ttk.Style()
        text_frame.style.theme_use("default")
        text_frame.configure(background="white")
        text_frame.pack(fill=BOTH)

        textbox_encrypted_message = Text(text_frame)
        textbox_encrypted_message.pack(fill=BOTH, side=LEFT, padx=10, pady=10)
        textbox_encrypted_message.insert("1.0", self.ubyte_arr_to_hex_string(self.encrypted_message, 0))
        textbox_encrypted_message.config(state=DISABLED)

        scroll_button = ttk.Scrollbar(text_frame, command=textbox_encrypted_message.yview)
        scroll_button.pack(side=LEFT, fill=BOTH)
        textbox_encrypted_message['yscrollcommand'] = scroll_button.set

        # Button frame configuration
        button_frame = Frame(popup)
        button_frame.style=ttk.Style()
        button_frame.style.theme_use("default")
        button_frame.configure(background="white")
        button_frame.pack()

        return_button = Button(button_frame, text="Izađi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=(lambda : popup.destroy()))
        return_button.pack(side=LEFT, padx=20)

    # Public key edit window
    def textbox_public_key_window(self):
        if(self.public_key == None):
            return
        
        # Popup window configuration
        popup = Toplevel(self)
        popup.style = ttk.Style()
        popup.style.theme_use("default")
        popup.configure(background="white")
        popup.title("Izmjena javnog ključa")
        popup.geometry("700x520+300+150")
        
        Label(popup, text = "JAVNI KLJUČ", font=self.text_font, bg="white").pack(pady=(10, 5))
        
        # Text frame configuration
        text_frame = Frame(popup)
        text_frame.style=ttk.Style()
        text_frame.style.theme_use("default")
        text_frame.configure(background="white")
        text_frame.pack(fill=BOTH)

        self.textbox_public_key = Text(text_frame)
        self.textbox_public_key.pack(fill=BOTH, side=LEFT, padx=10, pady=10)
        self.textbox_public_key.insert("1.0", self.ubyte_arr_to_hex_string(self.public_key, 0))
        
        scroll_button = ttk.Scrollbar(text_frame, command=self.textbox_public_key.yview)
        scroll_button.pack(side=LEFT, fill=BOTH)
        self.textbox_public_key['yscrollcommand'] = scroll_button.set

        # Button frame configuration
        button_frame = Frame(popup)
        button_frame.style=ttk.Style()
        button_frame.style.theme_use("default")
        button_frame.configure(background="white")
        button_frame.pack()

        save_button = Button(button_frame, text="Spremi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.save_public_key_edit)
        save_button.pack(side=LEFT, padx=20)

        return_button = Button(button_frame, text="Izađi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=(lambda : popup.destroy()))
        return_button.pack(side=LEFT, padx=20)


    # Private key edit window
    def textbox_private_key_window(self):
        if(self.private_key == None):
            return

        popup = Toplevel(self)
        popup.style = ttk.Style()
        popup.style.theme_use("default")
        popup.configure(background="white")
        popup.title("Izmjena privatnog ključa")
        popup.geometry("700x520+300+150")
        
        Label(popup, text = "PRIVATNI KLJUČ", font=self.text_font, bg="white").pack(pady=(10, 5))
        
        text_frame = Frame(popup)
        text_frame.style=ttk.Style()
        text_frame.style.theme_use("default")
        text_frame.configure(background="white")
        text_frame.pack(fill=BOTH)

        self.textbox_private_key = Text(text_frame)
        self.textbox_private_key.pack(fill=BOTH, side=LEFT, padx=10, pady=10)
        self.textbox_private_key.insert("1.0", self.ubyte_arr_to_hex_string(self.private_key, 0))
        
        scroll_button = ttk.Scrollbar(text_frame, command=self.textbox_private_key.yview)
        scroll_button.pack(side=LEFT, fill=BOTH)
        self.textbox_private_key['yscrollcommand'] = scroll_button.set

        button_frame = Frame(popup)
        button_frame.style=ttk.Style()
        button_frame.style.theme_use("default")
        button_frame.configure(background="white")
        button_frame.pack()

        save_button = Button(button_frame, text="Spremi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.save_private_key_edit)
        save_button.pack(side=LEFT, padx=20)

        return_button = Button(button_frame, text="Izađi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=(lambda : popup.destroy()))
        return_button.pack(side=LEFT, padx=20)


    # Digital signature edit window
    def textbox_signature_window(self):
        if(self.signature == None):
            return

        popup = Toplevel(self)
        popup.style = ttk.Style()
        popup.style.theme_use("default")
        popup.configure(background="white")
        popup.title("Izmjena digitalnog potpisa")
        popup.geometry("700x520+300+150")
        
        Label(popup, text = "DIGITALNI POTPIS", font=self.text_font, bg="white").pack(pady=(10, 5))
        
        text_frame = Frame(popup)
        text_frame.style=ttk.Style()
        text_frame.style.theme_use("default")
        text_frame.configure(background="white")
        text_frame.pack(fill=BOTH)

        self.textbox_signature = Text(text_frame)
        self.textbox_signature.pack(fill=BOTH, side=LEFT, padx=10, pady=10)
        self.textbox_signature.insert("1.0", self.ubyte_arr_to_hex_string(self.signature, 0))

        scroll_button = ttk.Scrollbar(text_frame, command=self.textbox_signature.yview)
        scroll_button.pack(side=LEFT, fill=BOTH)
        self.textbox_signature['yscrollcommand'] = scroll_button.set

        button_frame = Frame(popup)
        button_frame.style=ttk.Style()
        button_frame.style.theme_use("default")
        button_frame.configure(background="white")
        button_frame.pack()

        save_button = Button(button_frame, text="Spremi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=self.save_signature_edit)
        save_button.pack(side=LEFT, padx=20)

        return_button = Button(button_frame, text="Izađi", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=self.button_font, bg="#f5f5f5", command=(lambda : popup.destroy()))
        return_button.pack(side=LEFT, padx=20)


    # Home screen
    def home_screen(self):
        self.clear_screen()

        # Home screen font intialization
        button_font = font.Font(family='Calibri', size=20, weight='normal')
        title_font = font.Font(family='Calibri', size=32, weight='normal')
        
        self.pack(fill=BOTH, expand=True)

        # Home screen frame configuration
        title_label = Label(self, text="CRYSTALS - DILITHIUM", font=title_font, bg="white")
        title_label.pack(side=TOP, pady=40)
        digital_sginature_button = Button(self, text="DIGITALNI POTPIS", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=button_font, bg="white", command=self.digital_sginature_screen)
        digital_sginature_button.pack(side=LEFT, fill=BOTH, expand=True)
        encryption_button = Button(self, text="ENKRIPCIJA", relief="solid", fg="black",highlightbackground = "black", highlightthickness=1, bd=0, font=button_font, bg="white", command=self.encryption_screen)
        #encryption_button.pack(side=RIGHT, fill=BOTH, expand=True)


# Main program
def main():
    root = Tk()
    root.geometry("1000x560+300+150")

    app = App()

    root.mainloop()


main()