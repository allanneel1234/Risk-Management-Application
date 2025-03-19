import customtkinter as ctk
import sqlite3
import pandas as pd
import numpy as np
import requests
import bcrypt
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import io
from tkinter import messagebox

from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

import tkinter.filedialog as fd
import os



# Constants
API_KEY = 'RJYEZ9A2Y59DA2SA'
DEFAULT_CONFIDENCE_LEVEL = 0.95

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Database setup
def setup_user_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()





def view_users_window(parent):
    def fetch_users():
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT username, role FROM users')
        users = c.fetchall()
        conn.close()
        return users

    def fetch_and_display_users():
        users = fetch_users()
        user_count = len(users)
        if users:
            users_text = "\n".join([f"Username: {user[0]}, Role: {user[1]}" for user in users])
            users_textbox.delete(1.0, ctk.END)
            users_textbox.insert(ctk.END, users_text)
            count_label.configure(text=f"Total Users: {user_count}")
            user_dropdown.configure(values=[user[0] for user in users])
            user_dropdown.set(users[0][0] if users else "")
        else:
            users_textbox.delete(1.0, ctk.END)
            users_textbox.insert(ctk.END, "No users registered.")
            count_label.configure(text="Total Users: 0")
            user_dropdown.configure(values=[])
            user_dropdown.set("")

    def drop_user():
        selected_user = user_dropdown.get()
        if selected_user:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('DELETE FROM users WHERE username = ?', (selected_user,))
            conn.commit()
            conn.close()
            fetch_and_display_users()

    view_users_root = ctk.CTkToplevel(parent)
    view_users_root.geometry("600x800")
    view_users_root.title("View and Manage Users")

    ctk.CTkLabel(view_users_root, text="Registered Users:", font=("Arial", 16)).pack(pady=10)

    count_label = ctk.CTkLabel(view_users_root, text="Total Users: 0", font=("Arial", 12))
    count_label.pack(pady=5)

    users_textbox = ctk.CTkTextbox(view_users_root, wrap='word', font=("Arial", 12))
    users_textbox.pack(fill='both', expand=True, padx=10, pady=10)

    user_dropdown = ctk.CTkComboBox(view_users_root, font=("Arial", 12))
    user_dropdown.pack(pady=5)

    drop_button = ctk.CTkButton(view_users_root, text="Drop User", command=drop_user, font=("Arial", 12))
    drop_button.pack(pady=5)

    refresh_button = ctk.CTkButton(view_users_root, text="Refresh", command=fetch_and_display_users, font=("Arial", 12))
    refresh_button.pack(pady=5)

    close_button = ctk.CTkButton(view_users_root, text="Close", command=view_users_root.destroy, font=("Arial", 12))
    close_button.pack(pady=5)

    # Initialize dropdown and display users
    fetch_and_display_users()



def setup_stock_db():
    conn = sqlite3.connect('stock_data.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS stocks (
            symbol TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            open REAL,
            high REAL,
            low REAL,
            close REAL,
            volume INTEGER,
            PRIMARY KEY (symbol, timestamp)
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password, role):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  (username, hashed_password, role))
        conn.commit()
        messagebox.showinfo("Success", f"{role.capitalize()} registration successful")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists")
    conn.close()

def login_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password, role FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return result[1]
    else:
        return None

def fetch_stock_data(api_key, symbol):
    url = f'https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol={symbol}&apikey={api_key}&outputsize=full&datatype=csv'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.content.decode('utf-8')
        df = pd.read_csv(io.StringIO(data))
        if df.empty or 'timestamp' not in df.columns:
            messagebox.showerror("Error", f"No valid data found for symbol {{  {symbol}  }}")
            return None
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        df.sort_index(inplace=True)
        store_stock_data(df, symbol)
        return df
    else:
        messagebox.showerror("Error", "Failed to fetch stock data")
        return None

def store_stock_data(df, symbol):
    conn = sqlite3.connect('stock_data.db')
    c = conn.cursor()
    for index, row in df.iterrows():
        timestamp_str = index.strftime('%Y-%m-%d')
        c.execute('''
            INSERT OR REPLACE INTO stocks (symbol, timestamp, open, high, low, close, volume)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (symbol, timestamp_str, row['open'], row['high'], row['low'], row['close'], row['volume']))
    conn.commit()
    conn.close()

def fetch_data_from_db(symbol):
    conn = sqlite3.connect('stock_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM stocks WHERE symbol = ? ORDER BY timestamp', (symbol,))
    rows = c.fetchall()
    conn.close()
    if rows:
        df = pd.DataFrame(rows, columns=['symbol', 'timestamp', 'open', 'high', 'low', 'close', 'volume'])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        return df
    else:
        return None

def calculate_var(df, confidence_level):
    df['daily_return'] = df['close'].pct_change()
    df.dropna(inplace=True)
    sorted_returns = np.sort(df['daily_return'])
    index = int((1 - confidence_level) * len(sorted_returns))
    var = sorted_returns[index]
    return var

def calculate_cvar(df, confidence_level):
    df['daily_return'] = df['close'].pct_change()
    df.dropna(inplace=True)
    sorted_returns = np.sort(df['daily_return'])
    index = int((1 - confidence_level) * len(sorted_returns))
    var = sorted_returns[index]
    cvar = sorted_returns[:index].mean()
    return cvar

def generate_report(parent, df, var, cvar, symbol, confidence_level):
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(df.index, df['close'], label='Closing Price')
    ax.axhline(y=var, color='r', linestyle='--', label=f'VaR: {var:.3f}')
    ax.axhline(y=cvar, color='g', linestyle='--', label=f'CVaR: {cvar:.3f}')
    ax.set_title(f"Stock Data for {symbol} (Confidence Level: {confidence_level:.0%})")
    ax.set_xlabel("Date")
    ax.set_ylabel("Price")
    ax.legend()

    canvas = FigureCanvasTkAgg(fig, master=parent)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True)

    var_label = ctk.CTkLabel(parent, text=f"Value-at-Risk ({confidence_level:.0%} confidence): {var:.2%}",
                             font=("Arial", 14))
    var_label.pack(pady=(10, 5))
    cvar_label = ctk.CTkLabel(parent, text=f"Conditional Value-at-Risk ({confidence_level:.0%} confidence): {cvar:.2%}",
                              font=("Arial", 14))
    cvar_label.pack(pady=(5, 15))

def generate_report_file(df, symbol, var, cvar, confidence_level):
    with open(f"{symbol}_report_{confidence_level:.0%}.txt", "w") as f:
        f.write(f"Value-at-Risk ({confidence_level:.0%} confidence): {var:.2%}\n")
        f.write(f"Conditional Value-at-Risk ({confidence_level:.0%} confidence): {cvar:.2%}\n")
        f.write("\nStock Data:\n")
        f.write("Date,Open,High,Low,Close,Volume\n")
        for idx, row in df.iterrows():
            f.write(f"{idx.date()},{row['open']},{row['high']},{row['low']},{row['close']},{row['volume']}\n")

def check_alerts(df, var, cvar):
    latest_data = df.iloc[-1]
    if latest_data['close'] < var:
        messagebox.showwarning("Alert", f"Stock price is below VaR: {latest_data['close']:.2f}")
    if latest_data['close'] < cvar:
        messagebox.showwarning("Alert", f"Stock price is below CVaR: {latest_data['close']:.2f}")


def generate_pdf_report(df, symbol, var, cvar, confidence_level):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, f"Stock Data Report for {symbol}", ln=True, align='C')

    # VaR and CVaR
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.cell(200, 10, f"Value-at-Risk ({confidence_level:.0%} confidence): {var:.2%}", ln=True)
    pdf.cell(200, 10, f"Conditional Value-at-Risk ({confidence_level:.0%} confidence): {cvar:.2%}", ln=True)

    # Table Header
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(30, 10, "Date", 1)
    pdf.cell(30, 10, "Open", 1)
    pdf.cell(30, 10, "High", 1)
    pdf.cell(30, 10, "Low", 1)
    pdf.cell(30, 10, "Close", 1)
    pdf.cell(30, 10, "Volume", 1)
    pdf.ln()

    # Table Data
    pdf.set_font("Arial", size=12)
    for idx, row in df.iterrows():
        pdf.cell(30, 10, idx.strftime('%Y-%m-%d'), 1)
        pdf.cell(30, 10, f"{row['open']:.2f}", 1)
        pdf.cell(30, 10, f"{row['high']:.2f}", 1)
        pdf.cell(30, 10, f"{row['low']:.2f}", 1)
        pdf.cell(30, 10, f"{row['close']:.2f}", 1)
        pdf.cell(30, 10, str(row['volume']), 1)
        pdf.ln()

    pdf_file_name = f"{symbol}_report_{confidence_level:.0%}.pdf"
    pdf.output(pdf_file_name)
    return pdf_file_name

def save_pdf_report(pdf_file_name):
    try:
        # Open a save dialog for the user to select where to save the PDF
        save_path = fd.asksaveasfilename(defaultextension=".pdf",
                                         filetypes=[("PDF files", "*.pdf")],
                                         initialfile=pdf_file_name)
        if save_path:
            # Move the generated PDF to the selected location
            os.rename(pdf_file_name, save_path)
            messagebox.showinfo("Success", f"Report saved: {save_path}")
    except OSError as e:
        messagebox.showerror("Error", f"Failed to save report: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


def send_email_report(receiver_email, subject, body, attachment_path):
    sender_email = "allanneel1234@gmail.com"  # Replace with your email
    password = "qtxpyooovqmgekbv"  # Replace with your email password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Open and attach the file
        with open(attachment_path, "rb") as attachment:
            p = MIMEBase('application', 'octet-stream')
            p.set_payload(attachment.read())
            encoders.encode_base64(p)
            p.add_header('Content-Disposition', f"attachment; filename= {attachment_path}")
            msg.attach(p)

        # Connect to the server and send the email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()

        messagebox.showinfo("Success", "Email sent successfully!")
    except smtplib.SMTPRecipientsRefused:
        messagebox.showerror("Email Error",
                             "The recipient email address is invalid. Please check the email address and try again.")
    except smtplib.SMTPAuthenticationError as e:
        messagebox.showerror("Email Error", f"Authentication failed: {e}")
    except smtplib.SMTPException as e:
        messagebox.showerror("Email Error", f"Failed to send email: {e}")
    except TimeoutError as e:
        messagebox.showerror("Email Error",
                             "Failed to send email: Timeout. Please check your internet connection and Gmail settings.")
    except Exception as e:
        messagebox.showerror("Email Error", f"An error occurred: {e}")


def main_interface(role, username):
    confidence_level = ctk.DoubleVar(value=DEFAULT_CONFIDENCE_LEVEL)

    def fetch_and_display_data():
        symbol = symbol_entry.get().upper()
        df = fetch_data_from_db(symbol)
        if df is None:
            df = fetch_stock_data(API_KEY, symbol)
        if df is not None:
            conf_level = confidence_level.get()
            var = calculate_var(df, conf_level)
            cvar = calculate_cvar(df, conf_level)

            generate_report(scrollable_frame, df, var, cvar, symbol, conf_level)


            # Generate and Save PDF Report
            pdf_report_path = generate_pdf_report(df, symbol, var, cvar, conf_level)
            messagebox.showinfo("Success", f"Report generated: {pdf_report_path}")

            # Save and Open PDF Buttons
            save_button = ctk.CTkButton(scrollable_frame, text="Save PDF", font=("Arial", 12),
                                        command=lambda: save_pdf_report(pdf_report_path))
            save_button.pack(pady=5)



            # Ask if the user wants to email the report
            if messagebox.askyesno("Send Report", "Do you want to send this report via email?"):
                recipient_email = ctk.CTkEntry(
                    scrollable_frame,
                    placeholder_text="Enter recipient email",
                    font=("Arial", 12),
                    width=250,  # Adjust the width as needed
                    height=30  # Adjust the height as needed
                )
                recipient_email.pack(pady=5)
                send_button = ctk.CTkButton(scrollable_frame, text="Send Email", font=("Arial", 12),
                                            command=lambda: send_email_report(recipient_email.get(),
                                                                              f"Stock Report for {symbol}",
                                                                              f"Attached is the stock report for {symbol}.",
                                                                              pdf_report_path))
                send_button.pack(pady=5)

            # generate_report_file(df, symbol, var, cvar, conf_level)
            check_alerts(df, var, cvar)

    def view_users():
        view_users_window(root)

    def logout():
        # Unbind events or cleanup if necessary
        confidence_slider.unbind("<Motion>")
        root.quit()
        root.withdraw()
        login_window()

    def password_validation(password):
        """
        Validates the password based on specific criteria.
        Returns a list of error messages if the password doesn't meet the criteria.
        """
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            errors.append("Password must contain at least one special character.")

        return errors

    def admin_register_window(parent):
        def attempt_register():
            new_admin_username = new_admin_username_entry.get()
            new_admin_password = new_admin_password_entry.get()

            validation_errors = password_validation(new_admin_password)
            if validation_errors:
                messagebox.showerror("Password Error", "\n".join(validation_errors))
                return

            register_user(new_admin_username, new_admin_password, 'admin')
            register_root.destroy()

        register_root = ctk.CTkToplevel(parent)
        register_root.geometry("600x400")
        register_root.title("Admin Register")

        ctk.CTkLabel(register_root, text="New Admin Username:", font=("Arial", 12)).pack(pady=15)
        new_admin_username_entry = ctk.CTkEntry(register_root, font=("Arial", 12))
        new_admin_username_entry.pack(pady=5)

        ctk.CTkLabel(register_root, text="New Admin Password:", font=("Arial", 12)).pack(pady=5)
        new_admin_password_entry = ctk.CTkEntry(register_root, show="*", font=("Arial", 12))
        new_admin_password_entry.pack(pady=5)

        ctk.CTkLabel(register_root,
                     text="Password must contain at least:\n- 8 characters\n- 1 uppercase letter\n- 1 lowercase letter\n- 1 digit\n- 1 special character",
                     font=("Arial", 15)).pack(pady=10)

        ctk.CTkButton(register_root, text="Register", command=attempt_register, font=("Arial", 12)).pack(pady=10)
        ctk.CTkButton(register_root, text="Cancel", command=register_root.destroy, font=("Arial", 12)).pack(pady=5)

    def user_register_window(parent):
        def attempt_register_user():
            new_username = new_username_entry.get()
            new_password = new_password_entry.get()

            validation_errors = password_validation(new_password)
            if validation_errors:
                messagebox.showerror("Password Error", "\n".join(validation_errors))
                return

            register_user(new_username, new_password, 'user')
            register_root.destroy()

        register_root = ctk.CTkToplevel(parent)
        register_root.geometry("600x400")
        register_root.title("User Register")

        ctk.CTkLabel(register_root, text="New Username:", font=("Arial", 12)).pack(pady=15)
        new_username_entry = ctk.CTkEntry(register_root, font=("Arial", 12))
        new_username_entry.pack(pady=5)

        ctk.CTkLabel(register_root, text="New Password:", font=("Arial", 12)).pack(pady=5)
        new_password_entry = ctk.CTkEntry(register_root, show="*", font=("Arial", 12))
        new_password_entry.pack(pady=5)

        ctk.CTkLabel(register_root,
                     text="Password must contain at least:\n- 8 characters\n- 1 uppercase letter\n- 1 lowercase letter\n- 1 digit\n- 1 special character",
                     font=("Arial", 15)).pack(pady=10)

        ctk.CTkButton(register_root, text="Register", command=attempt_register_user, font=("Arial", 12)).pack(pady=10)
        ctk.CTkButton(register_root, text="Cancel", command=register_root.destroy, font=("Arial", 12)).pack(pady=5)

    root = ctk.CTk()
    root.geometry("800x600")
    root.title(f"{role.capitalize()} Interface")

    main_frame = ctk.CTkFrame(root)
    main_frame.pack(fill='both', expand=True)

    # Create a scrollable frame
    scrollable_frame = ctk.CTkScrollableFrame(main_frame)
    scrollable_frame.pack(fill='both', expand=True)

    login_frame = ctk.CTkFrame(scrollable_frame)
    login_frame.pack(fill='both', expand=True)

    ctk.CTkLabel(login_frame, text=f"Welcome, {role.capitalize()} {username}!", font=("Arial", 16)).pack(pady=20)

    if role == 'admin':
        ctk.CTkButton(login_frame, text="Register Admin", command=lambda: admin_register_window(root)).pack(pady=10)
        ctk.CTkButton(login_frame, text="Register User", command=lambda: user_register_window(root)).pack(pady=10)
        ctk.CTkButton(login_frame, text="View Registered Users", command=view_users).pack(pady=10)
    symbol_entry = ctk.CTkEntry(scrollable_frame, placeholder_text="Enter stock symbol e.g., AAPL", font=("Arial", 14),width= 250)
    symbol_entry.pack(pady=10)

    # Add confidence level slider
    # confidence_slider = ctk.CTkSlider(scrollable_frame, from_=0.50, to=0.99, number_of_steps=10, variable=confidence_level)
    confidence_slider = ctk.CTkSlider(scrollable_frame, from_=0.050, to=0.99, number_of_steps=10,variable=confidence_level)
    confidence_slider.pack(pady=10)

    confidence_label = ctk.CTkLabel(scrollable_frame, text=f"Confidence Level: {confidence_level.get():.0%}", font=("Arial", 12))
    confidence_label.pack(pady=5)

    # Update slider value label when slider is moved
    def update_confidence_label(event):
        confidence_label.configure(text=f"Confidence Level: {confidence_level.get():.0%}")

    confidence_slider.bind("<Motion>", update_confidence_label)

    ctk.CTkButton(scrollable_frame, text="Fetch and Display Data", command=fetch_and_display_data, font=("Arial", 14)).pack(pady=10)
    ctk.CTkButton(scrollable_frame, text="Logout", command=logout, font=("Arial", 14)).pack(pady=10)

    root.mainloop()

def login_window():
    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        role = login_user(username, password)
        if role:
            main_interface(role, username)
            login_root.destroy()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_help():
        help_message = (
            "Welcome to the Risk Management System!\n\n"
            "To get started:\n"
            "1. Enter your username and password in the respective fields.\n"
            "2. Click 'Login' to access your account.\n"
            "3. Once logged in, you will have access to various features including:\n"
            "- Fetching stock data\n"
            "- Generating risk reports such as VaR and CVaR\n"
            "- Viewing and managing reports\n\n"
            "If you have any issues or need further assistance, please contact support:\n"
            "Email: allanneel1234@gmail.com\n"
            "Phone: +254-700-548-808\n"
            "Support Hours: Monday to Friday, 9 AM - 5 PM\n"

        )
        messagebox.showinfo("Help", help_message)

    login_root = ctk.CTk()
    login_root.geometry("500x400")
    login_root.title("Risk Management System")

    # Adding a welcome text label
    ctk.CTkLabel(login_root, text="Welcome to the Risk Management System!", font=("Arial", 16), anchor="center").pack(pady=20)

    ctk.CTkLabel(login_root, text="Username:", font=("Arial", 12)).pack(pady=15)
    username_entry = ctk.CTkEntry(login_root, font=("Arial", 12))
    username_entry.pack(pady=5)

    ctk.CTkLabel(login_root, text="Password:", font=("Arial", 12)).pack(pady=5)
    password_entry = ctk.CTkEntry(login_root, show="*", font=("Arial", 12))
    password_entry.pack(pady=5)

    ctk.CTkButton(login_root, text="Login", command=attempt_login, font=("Arial", 12)).pack(pady=15)
    # Adding a Help button
    ctk.CTkButton(login_root, text="Help", command=show_help, font=("Arial", 12)).pack(pady=15)

    login_root.mainloop()

def run():
    setup_user_db()
    setup_stock_db()
    login_window()

if __name__ == "__main__":
    run()
