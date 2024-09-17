import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import firebase_admin
from firebase_admin import db, credentials
import io
import subprocess
import time
import string 
from scapy.all import rdpcap, sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import numpy as np
import pickle
import socket                          
import email
from email.message import EmailMessage
import smtplib
import ssl
email_sender = 'sender_email_id'
email_password = 'password'
email_reciever = 'reciever_email_id'
subject= 'IoT Security Alert'
body=""" 'Mirai Botnet Detected' """
em = EmailMessage()
em['From'] = email_sender
em['To'] = email_reciever
em['Subject'] = subject
em.set_content(body)
context = ssl.create_default_context()
# Define the main application class

from tkinter import PhotoImage
class MiraiApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Mirai Botnet Detection")
          # Set the window to fullscreen
        self.root.config(bg="black")  # Set the background color of the root window to black
        self.root.geometry("800x600")
        # Load background image
        self.load_background_image()

        # Add a label for the heading
        heading_label = tk.Label(self.root, text="Mirai Botnet Detection Tool", font=("Arial", 20, "bold"), fg="white", bg='#345263')
        heading_label.pack(pady=20)

        # Add two buttons for the options
        

        button_font = ("Helvetica", 12)
        button_width = 50
        button_height = 2

        # Styling for Live Packet Capture Button
        live_capture_button = tk.Button(self.root, text="Live Packet Capture", font=button_font,
                                        width=button_width, height=button_height, command=self.run_live_capture,
                                        bg="black", fg="white", borderwidth=0, highlightthickness=0, relief=tk.FLAT)
        live_capture_button.pack(pady=(190, 0))

        # Styling for Upload PCAP File Button
        upload_pcap_button = tk.Button(self.root, text="Upload PCAP File", font=button_font,
                                       width=button_width, height=button_height, command=self.upload_pcap_file,
                                       bg="grey", fg="white", borderwidth=0, highlightthickness=0, relief=tk.FLAT)
        upload_pcap_button.pack(pady=20)

        # Run the application
        self.root.mainloop()

    def load_background_image(self):
        try:
            background_image = tk.PhotoImage(file=r"back.png")
            bg_label = tk.Label(self.root, image=background_image)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)  # Make the background image cover the entire window
            bg_label.image = background_image
        except Exception as e:
            print("Error loading background image:", e)




# Create an instance of MiraiApp



    def run_live_capture(self):
        # Create an instance of the MiraiDetectionApp class for live packet capture
        self.root.geometry("725x475") 
        root = tk.Tk()
        app = MiraiDetectionApp(root)
        root.mainloop()

    def upload_pcap_file(self):
        # Ask the user to select a PCAP file
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        self.root.geometry("725x475") 
        if file_path:
            # Create a new window for displaying the results
            root = tk.Tk()
            app = MiraiDetectionApp(root, file_path)
            root.mainloop()

# Define the MiraiDetectionApp class

class MiraiDetectionApp:
    def __init__(self, root, file_path=None):
        self.root = root
        self.root.title("Mirai Attack Detection")
        self.root.geometry("800x600")
        # Load the background image
       

        # Create a label for the heading
        heading_label = tk.Label(self.root, text="Network Packet Analysis", font=("Arial", 16, "bold"),fg='cadetblue')
        heading_label.pack(pady=10)

        # Create a frame with a grey background
        grey_frame = ttk.Frame(self.root, relief='groove', padding=5, style='GreyFrame.TFrame')
        grey_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Create a scrolled text widget to display the output
        self.result_text = scrolledtext.ScrolledText(grey_frame, width=150, height=40, wrap=tk.WORD)
        self.result_text.pack()

        # Define custom tags for red and green text colors
        self.result_text.tag_configure("red", foreground="red")
        self.result_text.tag_configure("green", foreground="green")

        # Define the style for the grey frame
        style = ttk.Style()
        style.configure('GreyFrame.TFrame', background='lightgrey')

        # Add a "Download PDF" button to the GUI
        button_font = ("Helvetica", 12)
        button_width = 50
        button_height = 2
        
        download_button = tk.Button(self.root, text="Download PDF", font=button_font,
                                        width=button_width, height=button_height, command=self.download_pdf,
                                        bg="cadetblue", fg="white", borderwidth=0, highlightthickness=0, relief=tk.FLAT)
        download_button.pack(pady=0)

        # If file_path is None, perform live packet capture
        if file_path is None:
            # Part 1: Sniffing packets and writing them to a pcap file
            packets = sniff(prn=self.packet_summary, count=20)
            file_path = r"sample.pcap"
            wrpcap(file_path, packets)
            time.sleep(1)  # Add a delay to ensure the file is fully written

        # Part 2: Reading the pcap file and processing packets
        packets_read = rdpcap(file_path)
        self.process_packets(packets_read)

    
    def predict_with_model(self, pkl_file_path, source_ip_num, source_port, target_ip_num, target_port):
        # Load the trained classifier from the pickle file
        with open(pkl_file_path, 'rb') as file:
            classifier = pickle.load(file)
        
        # Convert IPv4-mapped IPv6 addresses to IPv4 format
        if ':' in target_ip_num:
            # Handle IPv6 address
            target_ip_num = target_ip_num.replace("::ffff:", "")
            # Extract the host address from the IPv6 address
            host_address = target_ip_num.split(':')[-1]
        else:
            # Handle IPv4 address
            host_address = target_ip_num.split('.')[-1]
    
        # Check if the host address consists only of hexadecimal characters
        if all(c in string.hexdigits for c in host_address):
            # Convert the host address to an integer
            host_address = int(host_address, 16)
        else:
            # If the host address contains non-hexadecimal characters, set it to None
            host_address = None
    
        # Convert IP addresses to integers
        source_ip_num_int = int.from_bytes(socket.inet_pton(socket.AF_INET6 if ':' in source_ip_num else socket.AF_INET, source_ip_num), 'big')
        target_ip_num_int = int.from_bytes(socket.inet_pton(socket.AF_INET6 if ':' in target_ip_num else socket.AF_INET, target_ip_num), 'big')
        
        # Create the feature vector including the source IP number, source port, target IP number, target port, and host address
        features = np.array([[source_ip_num_int, source_port, target_ip_num_int, target_port, host_address]])

        # Use the loaded classifier to predict the outcome
        y_pred = classifier.predict(features)

        # Assuming the classifier's prediction is the prediction result
        prediction = y_pred[0]

        # Return the prediction
        return prediction

    def process_packets(self, packets_read):
        # Initialize sets to track IP addresses and ports
        if not firebase_admin._apps:
            # Initialize Firebase
            cred = credentials.Certificate(r"C:path\credentials.json")
            firebase_admin.initialize_app(cred, {'databaseURL': 'firebase-realtime-databse-url'})
        
        srcip = set()
        destip = set()
        srcports = set()
        destports = set()
        ip_info = set()

        # Flag to check for Botnet detection
        flag = False

        # Process each packet
        for packet in packets_read:
            # Summarize packet information
            summary = self.packet_summary(packet)
            print(summary)  # Or you can do whatever you want with the summary
            
            if packet.haslayer(IP):
                # Handle IPv4 packets
                srcip.add(f"IPv4 -- {packet[IP].src}")
                destip.add(f"IPv4 -- {packet[IP].dst}")
                if packet.haslayer(TCP):
                    info = f"TCP -- {packet[IP].src} : {packet[TCP].sport} --> {packet[IP].dst} : {packet[TCP].dport}"
                    ip_info.add(info)
                    srcports.add(f"TCP -- {packet[TCP].sport}")
                    destports.add(f"TCP -- {packet[TCP].dport}")
            elif packet.haslayer(IPv6):
                # Handle IPv6 packets
                src_ipv4 = packet[IPv6].src.replace("::ffff:", "")
                dst_ipv4 = packet[IPv6].dst.replace("::ffff:", "")
                srcip.add(f"IPv6 -- {packet[IPv6].src}")
                destip.add(f"IPv6 -- {packet[IPv6].dst}")
                if packet.haslayer(TCP):
                    info = f"TCP -- {src_ipv4} : {packet[TCP].sport} --> {dst_ipv4} : {packet[TCP].dport}"
                    ip_info.add(info)
                    srcports.add(f"TCP -- {packet[TCP].sport}")
                    destports.add(f"TCP -- {packet[TCP].dport}")

        output_text = "\nSource IP Address\n------------------\n"
        output_text += '\n'.join(ip for ip in srcip if "IPv4" in ip or "IPv6" in ip)
        output_text += "\n\nDestination IP Address\n-----------------------\n"
        output_text += '\n'.join(ip for ip in destip if "IPv4" in ip or "IPv6" in ip)
        output_text += "\n\nSource Ports\n-------------\n"
        output_text += '\n'.join(srcports)
        output_text += "\n\nDestination Ports\n------------------\n"
        output_text += '\n'.join(destports)
        output_text += "\n\nPacket Requests and Responses\n------------------------------\n"
        output_text += '\n'.join(ip_info)

        # Add the general results text to the scrolled text widget
        self.result_text.insert(tk.END, output_text)
        ref = db.reference("/Mirai")
        
        # Check for Botnet detection (Telnet connection on ports 23 or 2323)
        for src in srcports:
            port = int(src[7:])
            if port == 23 or port == 2323:
                flag = True
                ref.set(1)
                break

        # Check for prediction using the model
        for dest in destip:
            target_ip_num = dest.split()[-1]
            print(target_ip_num)
        for targetport in destports: 
            target_port=int(targetport.split()[-1]) 
            for src_port in srcports:
                source_port = int(src_port.split()[-1])
                for sourceip in srcip:
                    source_ip_num = sourceip.split()[-1]     
                    
                    pkl_file_path = r"C:\path\classifier.pkl"
                    prediction = self.predict_with_model(pkl_file_path, source_ip_num, source_port, target_ip_num,target_port)
                    
                    # Check the prediction result and update the flag
                    if prediction == 1:
                        flag = True
                        break
                    
                       

        detection_text = ""
        if flag:
            try:
                            ref.set(1)
                            print("Value set to 1 in Firebase")
            except Exception as e:
                            print("Error setting value to 1:", e)
            detection_text = "\n\nMirai Botnet detected: Connection attempt to Telnet or Blacklisted IP's"
            self.result_text.insert(tk.END, detection_text, "red")
            self.send_email()
        else:
            try:
                            ref.set(0)
                            print("Value set to 0 in Firebase")
            except Exception as e:
                            print("Error setting value to 0:", e)
            detection_text = "\n\nNo Botnet detected"
            self.result_text.insert(tk.END, detection_text, "green")

    def packet_summary(self, packet):
        """Function to summarize packet information."""
        return packet.summary()

    def download_pdf(self):
        # Ask the user for the file name and path to save the PDF
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])

        if file_path:
            # Create a PDF file using the specified filename
            pdf = canvas.Canvas(file_path, pagesize=letter)

            # Split the text from the scrolled text widget into lines
            text_lines = self.result_text.get("1.0", tk.END).split('\n')

            # Set the starting position for the text
            y = letter[1] - 50

            # Add the lines of text to the PDF
            for line in text_lines:
                pdf.drawString(50, y, line)
                y -= 20  # Move down the page by 20 points

            # Save the PDF file
            pdf.save()

            # Show a success message
            messagebox.showinfo("Success", "PDF downloaded successfully!")

    def send_email(self):
        # Create a BytesIO object to store the PDF data
        pdf_buffer = io.BytesIO()

        # Create a PDF file using the BytesIO buffer
        pdf = canvas.Canvas(pdf_buffer, pagesize=letter)

        # Split the text from the scrolled text widget into lines
        text_lines = self.result_text.get("1.0", tk.END).split('\n')

        # Set the starting position for the text
        y = letter[1] - 50

        # Add the lines of text to the PDF
        for line in text_lines:
            pdf.drawString(50, y, line)
            y -= 20  # Move down the page by 20 points

        # Save the PDF content to the BytesIO buffer
        pdf.save()

        # Get the PDF data from the BytesIO buffer
        pdf_data = pdf_buffer.getvalue()

        # Close the BytesIO buffer
        pdf_buffer.close()

        # Create a message object
        msg = EmailMessage()
        msg['From'] = email_sender
        msg['To'] = email_reciever
        msg['Subject'] = subject
        msg.set_content(body)

        # Attach the PDF data
        msg.add_attachment(pdf_data, maintype='application', subtype='pdf', filename="packet_summary.pdf")

        # Send the email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.send_message(msg)

if __name__ == "__main__":
    # Create an instance of the MiraiApp class to start the application
    app = MiraiApp()
