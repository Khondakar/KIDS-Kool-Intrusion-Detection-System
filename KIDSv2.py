# KIDS v.2: Kool Intrusion Detection System
# Function : Monitoring change in the file system & folders
# Author : Khondakar
# Date: 23/Oct/2020

import logging
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from tkinter import *
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
import pandas as pd
import yagmail
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import easygui


class KIDS(PatternMatchingEventHandler, Observer):
    def __init__(self, path='.', patterns='*', logfunc=print):
        PatternMatchingEventHandler.__init__(self, patterns)
        Observer.__init__(self)
        self.schedule(self, path=path, recursive=True)
        self.log = logfunc

        # Set the format of logging info
        logging.basicConfig(level=logging.WARNING,
                            format='%(asctime)s - %(message)s',
                            datefmt='%d-%m-%Y %H:%M:%S',
                            handlers=[RotatingFileHandler('./KIDSFileMonitor.log', maxBytes=1000000, backupCount=10)])

    # This function is called when a file is created
    def on_created(self, event):
        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")  # dd/mm/YY H:M:S
        # print(dt_string + f" - Security Alert! ' {event.src_path} ' has been created!")
        self.log(dt_string + f" - Security Alert! ' {event.src_path} ' has been created!")
        logging.warning(f"Security Alert! ' {event.src_path} ' has been created!!")
        self.email_alert()  # send email alert for file system altered

    # This function is called when a file is deleted
    def on_deleted(self, event):
        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")  # dd/mm/YY H:M:S
        self.log(dt_string + f" - Security Alert! Files/folder deleted: {event.src_path}!")
        logging.warning(f"Security Alert! Files/folder deleted: {event.src_path}!")
        self.email_alert()  # send email alert for file system altered

    # This function is called when a file is modified
    def on_modified(self, event):
        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")  # dd/mm/YY H:M:S
        self.log(dt_string + f" - Security Alert! ' {event.src_path} ' has been modified!")
        logging.warning(f"Security Alert! ' {event.src_path} ' has been modified!")
        self.email_alert()  # send email alert for file system altered

    # This function is called when a file is renamed or moved
    def on_moved(self, event):
        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")  # dd/mm/YY H:M:S
        self.log(dt_string + f" - Security Alert! Files/folder moved or renamed: {event.src_path} to {event.dest_path}")
        logging.warning(f"Security Alert! Files/folder moved or renamed: ' {event.src_path} ' to ' {event.dest_path} '")
        self.email_alert()  # send email alert for file system altered

    # Email alert notification
    def email_alert(self):
        try:
            user = 'user1@gmail.com'
            app_password = 'user1password'  # google app password
            to = 'user2@gmail.com'
            # to = [‘user1@gmail.com’, ‘user2@yahoo.com’] # To send a group of recipients

            subject = '** SECURITY ALERT ** File System Changed!'
            content = ['SECURITY BREACHED! File system altered! Please check attached log file!', 'KIDSFileMonitor.log']
            try:
                with yagmail.SMTP(user, app_password) as yag:
                    yag.send(to, subject, content)
                    # self.log("Email successfully sent.")
            except:
                self.log("Error: Email can't send out")
        except FileNotFoundError:
            self.log("Email Alert Exception Error!")


class MAIN:
    def __init__(self):
        self.watchdog = None
        self.watch_path = '.'
        self.root = Tk()
        self.messagebox = Text(width=135, height=30)
        self.root.title("KIDS v2 - Kool Intrusion Detection System")
        self.messagebox.pack()

        # -----------------------------------------------------------------------------------------------------------
        # Configure menu items
        my_menu = Menu(self.root)
        self.root.config(menu=my_menu)

        # Create 'Scanner' menu items
        scanner_menu = Menu(my_menu, tearoff=0)  # tearoff use to remove dotted line in menu
        my_menu.add_cascade(label="Scanner", menu=scanner_menu)
        scanner_menu.add_command(label="Browse & Select folder", command=lambda: self.select_path())
        scanner_menu.add_separator()
        scanner_menu.add_command(label="Start Scanner", command=lambda: self.start_watchdog())
        scanner_menu.add_command(label="Stop Scanner", command=lambda: self.stop_watchdog())
        scanner_menu.add_separator()
        scanner_menu.add_command(label="Exit", command=self.root.quit)

        # Create 'Report' menu items
        report_menu = Menu(my_menu, tearoff=0)
        my_menu.add_cascade(label="Report", menu=report_menu)
        report_menu.add_command(label="Main report", command=lambda: self.display_report())
        report_menu.add_command(label="Collective report", command=lambda: self.collect_data())
        report_menu.add_separator()
        report_menu.add_command(label="Dashboard report", command=lambda: self.display_dashboard())

        # Create 'Search' menu items
        search_menu = Menu(my_menu, tearoff=0)
        my_menu.add_cascade(label="Search", menu=search_menu)
        search_menu.add_command(label="Search in Log file", command=lambda: self.search())

        # Create 'Alert' menu items
        alert_menu = Menu(my_menu, tearoff=0)
        my_menu.add_cascade(label="Alert", menu=alert_menu)
        alert_menu.add_command(label="Send email alert", command=lambda: self.email_alert())

        # Create 'Help' menu items
        help_menu = Menu(my_menu, tearoff=0)
        my_menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Getting started", command=lambda: self.getting_start())
        help_menu.add_separator()
        help_menu.add_command(label="About", command=lambda: self.about_help())
        # -----------------------------------------------------------------------------------------------------------

        self.root.mainloop()

    # Start the watchdog scanner
    def start_watchdog(self):
        self.messagebox.replace('1.0', 'end', '')  # clear/delete the existing content of text box widget tkinter
        if self.watchdog is None:
            self.watchdog = KIDS(path=self.watch_path, logfunc=self.log)
            self.watchdog.start()
            self.log('KIDS scanner is started & running..')
        else:
            self.log('KIDS scanner already running..')

    # Stop the watchdog scanner
    def stop_watchdog(self):
        if self.watchdog:
            self.watchdog.stop()
            self.watchdog = None
            self.log('KIDS scanner stopped!')
        else:
            self.log('KIDS scanner is not running!!')

    # Select folder/path for scanning
    def select_path(self):
        self.messagebox.replace('1.0', 'end', '')  # clear/delete the existing content of text box widget tkinter
        path = filedialog.askdirectory()
        if path:
            self.watch_path = path
            self.log(f'Folder & path selected for scanning: {path}')

    def log(self, message):
        self.messagebox.insert(END, f'{message}\n')
        self.messagebox.see(END)

    def our_command(self):
        my_label = Label(self.root, text="You clicked a dropdown menu").pack()

    def about_help(self):
        messagebox.showinfo(title="About KIDS", message="Kool Intrusion Detection System - KIDS Ver 2.0")

    def getting_start(self):
        try:
            self.messagebox.replace('1.0', 'end', '')  # clear/delete the existing content of text box widget tkinter
            file = open("./GettingStarted.txt")
            content = file.read()
            self.log(content)
            file.close()
        except FileNotFoundError:
            self.log("Exception error: File not found!")

    # Searching based on word
    def search(self):
        try:
            """Search for the given string in file and return lines containing that string,
                along with line numbers"""
            line_number = 0
            list_of_results = []
            file_name = 'KIDSFileMonitor.log'

            # clear/delete the existing content of text box widget tkinter
            self.messagebox.replace('1.0', 'end', '')

            # pop up dialogue box for asking user to search
            string_to_search = easygui.enterbox("Please Enter The Word You Want To Search In Log File")

            # Open the file in read only mode
            with open(file_name, 'r') as read_obj:
                # Read all lines in the file one by one
                for line in read_obj:
                    # For each line, check if line contains the string
                    line_number += 1
                    try:
                        if string_to_search in line:
                            # If yes, then add the line number & line as a tuple in the list
                            list_of_results.append((line_number, line.rstrip()))
                    except TypeError:
                        # self.log("Exception error: Operation cancel by the user!")
                        print("Exception error: Operation cancel by the user!")

            # Return list of tuples containing line numbers and lines where string is found
            # print('Total matched lines : ', len(list_of_results))
            self.log(f"Total matched lines :  {len(list_of_results)} ")

            # Display matching word with line number from log file
            for element in list_of_results:
                # print('Line = ', element[0], ' :: ', element[1])
                self.log(f"Line = {element[0]}  ::  {element[1]}")

        except FileNotFoundError:
            self.log("Exception error: File not exist!")

    # Display log report
    def display_report(self):
        try:
            self.messagebox.replace('1.0', 'end', '')  # clear/delete the existing content of text box widget tkinter
            file = open("./KIDSFileMonitor.log")
            content = file.read()
            self.log(content)
            file.close()
        except FileNotFoundError:
            self.log("Exception error: File not found!")

    # Prepare data for plotting graph in dash board
    def collect_data(self):
        try:
            occurrences = defaultdict(lambda: defaultdict(int))
            keys = {'created', 'modified', 'deleted', 'moved'}
            with open('KIDSFileMonitor.log', 'r') as f:
                for line in f:
                    date = line.split(' ')[0]
                    for key in keys:
                        if key in line:
                            occurrences[date][key] += 1

            # clear/delete the existing content of text box widget tkinter
            self.messagebox.replace('1.0', 'end', '')

            # Open file as write mode
            a = open('collect_data.csv', 'w')
            a.write('Date,Key,Count\n')

            # Only show date and total count of occurrence of events
            # print('Date,Key,Count')
            self.log('Date,Key,Count')
            for date in occurrences:
                for key in occurrences[date]:
                    self.log(date + ',' + key + ',' + str(occurrences[date][key]))
                    a = open('collect_data.csv', 'a')
                    a.write(date + ',' + key + ',' + str(occurrences[date][key]) + '\n')
                    a.close()
        except FileNotFoundError:
            self.log("Exception error: File not found!")

    # Email alert notification
    def email_alert(self):
        try:
            user = 'user1@gmail.com'
            app_password = 'password'  # google app password
            to = 'user2@gmail.com'
            # to = [‘user1@gmail.com’, ‘user2@yahoo.com’] # To send a group of recipients

            subject = '** SECURITY ALERT ** File System Changed!'
            content = ['SECURITY BREACHED! File system altered! Please check attached log file!', 'KIDSFileMonitor.log']
            try:
                with yagmail.SMTP(user, app_password) as yag:
                    yag.send(to, subject, content)
                    # clear/delete the existing content of text box widget tkinter
                    self.messagebox.replace('1.0', 'end', '')
                    self.log("Email sent successfully.")
            except:
                self.log("Error: Email can't send out")
        except FileNotFoundError:
            self.log("Email Alert Exception Error!")

    # Plotting graph
    def display_dashboard(self):
        try:
            # Select the csv file from current folder
            df = pd.read_csv("collect_data.csv")
            df.head()

            # Configure the bar chart here
            df.set_index(["Date", "Key"]).unstack("Key").plot(kind="bar", rot=0)

            # Put title and label for the bar chart
            plt.title('DASH BOARD REPORT - File System Changed Date & Events Types')
            plt.ylabel('Total Count of different events occurred in file system')
            plt.xlabel("DATE")

            # Display the bar chart graph
            plt.show()
        except FileNotFoundError:
            self.log("Exception error: Missing files!")


if __name__ == '__main__':
    MAIN()
