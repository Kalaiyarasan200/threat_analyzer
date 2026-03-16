import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse
import tkinter as tk
from tkinter import scrolledtext
import zipfile
from tkinter import filedialog
import re
import os
import matplotlib.pyplot as plt

# ==========================
# GLOBAL VARIABLES
# ==========================

apk_risk_score = 0
original_risk_score = 0

apk_size = 0
original_size = 0

apk_total_files = 0
original_total_files = 0

apk_dex_count = 0
apk_so_count = 0
apk_url_count = 0
apk_ip_count = 0
apk_suspicious_count = 0

original_db_count = 0
original_script_count = 0
original_url_count = 0
original_ip_count = 0

# ==========================
# GUI WINDOW
# ==========================

root = tk.Tk()
root.title("OSINT Web + APK Deep Vulnerability Scanner")
root.geometry("900x650")
root.configure(bg="white")

# ==========================
# TITLE
# ==========================

title = tk.Label(
    root,
    text="Advanced OSINT Web + APK Security Scanner",
    font=("Arial", 20, "bold"),
    fg="blue",
    bg="white"
)
title.pack(pady=15)

# ==========================
# STATUS LABEL
# ==========================

status_label = tk.Label(
    root,
    text="Status: Ready",
    font=("Arial", 11),
    fg="darkgreen",
    bg="white"
)
status_label.pack()

# ==========================
# URL INPUT
# ==========================

frame = tk.Frame(root, bg="white")
frame.pack(pady=10)

url_label = tk.Label(
    frame,
    text="Target URL:",
    font=("Arial", 12),
    fg="black",
    bg="white"
)
url_label.pack(side=tk.LEFT, padx=5)

url_entry = tk.Entry(frame, width=50, font=("Arial", 12))
url_entry.pack(side=tk.LEFT, padx=5)

# ==========================
# WEBSITE SCAN
# ==========================
def scan_target():

    output.delete(1.0, tk.END)

    url = url_entry.get().strip()

    if url == "":
        output.insert(tk.END, "Please enter a valid URL\n")
        return

    # ==========================
    # RISK SCORE VARIABLE
    # ==========================

    risk_score = 0

    output.insert(tk.END, "Scanning Target: " + url + "\n\n")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        output.insert(tk.END, "Error accessing URL: " + str(e))
        return

    soup = BeautifulSoup(response.text, "html.parser")
    parsed = urlparse(url)

    # ==========================
    # RESOURCE LINK ANALYSIS
    # ==========================

    output.insert(tk.END, "========== RESOURCE LINK ANALYSIS ==========\n\n")

    output.insert(tk.END, "Main HTML Page: " + url + "\n\n")

    # CSS FILES
    output.insert(tk.END, "🎨 CSS Files\n")

    css_links = set()

    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            css_links.add(urljoin(url, href))

    if css_links:
        for css in css_links:
            output.insert(tk.END, css + "\n")
    else:
        output.insert(tk.END, "No CSS files found\n")

    # JAVASCRIPT FILES
    output.insert(tk.END, "\n⚙️ JavaScript Files\n")

    js_links = set()

    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_links.add(urljoin(url, src))

    if js_links:
        for js in js_links:
            output.insert(tk.END, js + "\n")
    else:
        output.insert(tk.END, "No JS files found\n")

    # INTERNAL LINKS
    output.insert(tk.END, "\n🔗 Internal Links\n")

    internal_links = set()

    for a in soup.find_all("a", href=True):
        link = urljoin(url, a["href"])
        if parsed.netloc in urlparse(link).netloc:
            internal_links.add(link)

    if internal_links:
        for link in internal_links:
            output.insert(tk.END, link + "\n")
    else:
        output.insert(tk.END, "No internal links found\n")

    # EXTERNAL LINKS
    output.insert(tk.END, "\n🌍 External Links\n")

    external_links = set()

    for a in soup.find_all("a", href=True):
        link = urljoin(url, a["href"])
        if parsed.netloc not in urlparse(link).netloc:
            external_links.add(link)

    if external_links:
        for link in external_links:
            output.insert(tk.END, link + "\n")
    else:
        output.insert(tk.END, "No external links found\n")

    # ==========================
    # VULNERABILITY SCAN
    # ==========================

    output.insert(tk.END, "\n========== VULNERABILITY SCAN ==========\n\n")

    # Sensitive files
    output.insert(tk.END, "[+] Checking Sensitive Files\n")

    sensitive_files = {
        ".env": "Environment File Exposure",
        ".git/HEAD": "Git Repository Exposure",
        "config.php": "Configuration File Exposure",
        "backup.zip": "Backup File Exposure",
        "database.sql": "Database Dump Exposure"
    }

    found = False

    for file, threat in sensitive_files.items():

        test_url = urljoin(url, file)

        try:
            res = requests.get(test_url, timeout=5)

            if res.status_code == 200 and len(res.text) > 50:
                found = True
                risk_score += 25

                output.insert(tk.END, "⚠ Vulnerability Found\n")
                output.insert(tk.END, "URL: " + test_url + "\n")
                output.insert(tk.END, "Threat: " + threat + "\n\n")

        except:
            pass

    if not found:
        output.insert(tk.END, "✔ No Sensitive File Exposure Found\n")

    # HTML COMMENTS
    output.insert(tk.END, "\n[+] Checking HTML Comments\n")

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    found_comment = False

    for comment in comments:

        if any(keyword in comment.lower() for keyword in ["password", "secret", "api", "token"]):
            found_comment = True
            risk_score += 10

            output.insert(tk.END, "⚠ Sensitive Comment Found\n")
            output.insert(tk.END, comment + "\n\n")

    if not found_comment:
        output.insert(tk.END, "✔ No Sensitive Comments Found\n")

    # SECURITY HEADERS
    output.insert(tk.END, "\n[+] Checking Security Headers\n")

    headers = response.headers

    missing_headers = {
        "X-Frame-Options": "Clickjacking",
        "Content-Security-Policy": "XSS",
        "Strict-Transport-Security": "SSL Strip"
    }

    header_missing = False

    for header, attack in missing_headers.items():

        if header not in headers:
            header_missing = True
            risk_score += 10

            output.insert(tk.END, "⚠ Missing Header: " + header + "\n")
            output.insert(tk.END, "Possible Attack: " + attack + "\n\n")

    if not header_missing:
        output.insert(tk.END, "✔ All Important Headers Present\n")

    # FORM CHECK
    output.insert(tk.END, "\n[+] Checking Forms\n")

    forms = soup.find_all("form")

    risky_form = False

    for form in forms:

        method = form.get("method", "get").lower()
        action = form.get("action")

        if method == "get":
            risky_form = True
            risk_score += 15

            output.insert(tk.END, "⚠ Form uses GET Method\n")
            output.insert(tk.END, "Action: " + str(action) + "\n\n")

    if not risky_form:
        output.insert(tk.END, "✔ No Risky Forms Detected\n")
    # ==========================
    # DATA EXTRACTION FROM WEBSITE
    # ==========================

    output.insert(tk.END, "\n========== DATA EXTRACTION ==========\n\n")

    # Website Title
    if soup.title:
        output.insert(tk.END, "Website Title: " + soup.title.string + "\n\n")

    # Meta Description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        output.insert(tk.END, "Meta Description: " + meta_desc.get("content", "") + "\n\n")

    # Extract Emails
    import re
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", response.text)

    if emails:
        output.insert(tk.END, "Emails Found:\n")
        for email in set(emails):
            output.insert(tk.END, email + "\n")
        output.insert(tk.END, "\n")

    # Extract Phone Numbers
    phones = re.findall(r"\+?\d[\d\s\-]{8,}\d", response.text)

    if phones:
        output.insert(tk.END, "Phone Numbers Found:\n")
        for phone in set(phones):
            output.insert(tk.END, phone + "\n")
        output.insert(tk.END, "\n")

    # Extract Images
    images = soup.find_all("img")

    if images:
        output.insert(tk.END, "Images Found:\n")
        for img in images:
            src = img.get("src")
            if src:
                output.insert(tk.END, urljoin(url, src) + "\n")
        output.insert(tk.END, "\n")

    # Page Text Preview
    text_content = soup.get_text()
    preview = text_content.strip()[:500]

    output.insert(tk.END, "Page Text Preview:\n")
    output.insert(tk.END, preview + "\n\n")

    # ==========================
    # RISK SCORE ANALYSIS
    # ==========================

    if risk_score > 100:
        risk_score = 100

    output.insert(tk.END, "\n========== WEBSITE RISK SCORE ==========\n")
    output.insert(tk.END, "Risk Score: " + str(risk_score) + "/100\n")

    if risk_score <= 20:
        output.insert(tk.END, "Threat Level: LOW RISK\n")
    elif risk_score <= 50:
        output.insert(tk.END, "Threat Level: MEDIUM RISK\n")
    else:
        output.insert(tk.END, "Threat Level: HIGH RISK\n")

    output.insert(tk.END, "\n========== SCAN COMPLETED ==========\n")

# ==========================
# APK DEEP SCAN
# ==========================

def scan_apk():

    global apk_risk_score, apk_size
    global apk_total_files, apk_dex_count, apk_so_count
    global apk_url_count, apk_ip_count, apk_suspicious_count

    status_label.config(text="Status: Deep Scanning APK...")
    root.update()

    output.delete(1.0, tk.END)

    apk_path=filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files","*.apk")]
    )

    if apk_path=="":
        return

    # reset counters
    apk_dex_count=0
    apk_so_count=0
    apk_url_count=0
    apk_ip_count=0
    apk_suspicious_count=0

    apk_size = os.path.getsize(apk_path)/(1024*1024)

    output.insert(tk.END,"APK Size: "+str(round(apk_size,2))+" MB\n")

    risk_score=0

    apk=zipfile.ZipFile(apk_path,'r')
    file_list=apk.namelist()

    apk_total_files=len(file_list)

    output.insert(tk.END,"Total Files: "+str(apk_total_files)+"\n\n")

    output.insert(tk.END,"DEX FILES\n")

    for file in file_list:
        if file.endswith(".dex"):
            apk_dex_count+=1
            output.insert(tk.END,file+"\n")
            risk_score+=5

    output.insert(tk.END,"\nNative Libraries\n")

    for file in file_list:
        if file.endswith(".so"):
            apk_so_count+=1
            output.insert(tk.END,file+"\n")
            risk_score+=5

    output.insert(tk.END,"\nString Analysis\n")

    suspicious_keywords=["password","token","apikey","secret","admin"]

    for file in file_list:

        try:

            data=apk.read(file).decode(errors="ignore")

            urls=re.findall(r'https?://[^\s"]+',data)
            ips=re.findall(r'\d+\.\d+\.\d+\.\d+',data)

            for u in urls:
                apk_url_count+=1
                output.insert(tk.END,"URL: "+u+"\n")

            for ip in ips:
                apk_ip_count+=1
                output.insert(tk.END,"IP: "+ip+"\n")
                risk_score+=2

            for key in suspicious_keywords:
                if key in data.lower():
                    apk_suspicious_count+=1
                    output.insert(tk.END,"Suspicious Keyword: "+key+"\n")
                    risk_score+=3

        except:
            pass

    if risk_score>100:
        risk_score=100

    apk_risk_score=risk_score

    output.insert(tk.END,"\nAPK RISK SCORE: "+str(risk_score)+"/100\n")

# ==========================
# ORIGINAL APP SCAN
# ==========================

def scan_original_app():

    global original_risk_score, original_size
    global original_total_files, original_db_count
    global original_script_count, original_url_count, original_ip_count

    status_label.config(text="Status: Deep Scanning Data + OBB...")
    root.update()

    output.delete(1.0, tk.END)

    folder_path=filedialog.askdirectory()

    if folder_path=="":
        return

    # reset counters
    original_total_files=0
    original_db_count=0
    original_script_count=0
    original_url_count=0
    original_ip_count=0

    risk_score=0
    total_size=0

    for root_dir,dirs,files in os.walk(folder_path):

        for file in files:

            original_total_files+=1

            path=os.path.join(root_dir,file)

            total_size+=os.path.getsize(path)

            if file.endswith(".db") or file.endswith(".sqlite"):
                original_db_count+=1
                output.insert(tk.END,"Database: "+file+"\n")
                risk_score+=5

            if file.endswith(".sh"):
                original_script_count+=1
                output.insert(tk.END,"Script: "+file+"\n")
                risk_score+=5

            try:

                with open(path,"r",errors="ignore") as f:

                    data=f.read()

                    urls=re.findall(r'https?://[^\s"]+',data)
                    ips=re.findall(r'\d+\.\d+\.\d+\.\d+',data)

                    for u in urls:
                        original_url_count+=1
                        output.insert(tk.END,"URL: "+u+"\n")

                    for ip in ips:
                        original_ip_count+=1
                        output.insert(tk.END,"IP: "+ip+"\n")

            except:
                pass

    original_size=total_size/(1024*1024)

    if risk_score>100:
        risk_score=100

    original_risk_score=risk_score

    output.insert(tk.END,"\nFolder Size: "+str(round(original_size,2))+" MB\n")
    output.insert(tk.END,"Total Files: "+str(original_total_files)+"\n")

    output.insert(tk.END,"\nORIGINAL APP RISK SCORE: "+str(original_risk_score)+"/100\n")

# ==========================
# COMPARISON (MAIN SUMMARY)
# ==========================

def compare_analysis():

    output.delete(1.0, tk.END)

    output.insert(tk.END,"\n========== MAIN COMPARISON SUMMARY ==========\n\n")

    output.insert(tk.END,"APK MAIN INFO\n")
    output.insert(tk.END,"-----------------\n")
    output.insert(tk.END,"Size: "+str(round(apk_size,2))+" MB\n")
    output.insert(tk.END,"Total Files: "+str(apk_total_files)+"\n")
    output.insert(tk.END,"DEX Files: "+str(apk_dex_count)+"\n")
    output.insert(tk.END,"Native Libraries: "+str(apk_so_count)+"\n")
    output.insert(tk.END,"Suspicious Keywords: "+str(apk_suspicious_count)+"\n")
    output.insert(tk.END,"URLs Found: "+str(apk_url_count)+"\n")
    output.insert(tk.END,"IPs Found: "+str(apk_ip_count)+"\n")
    output.insert(tk.END,"Risk Score: "+str(apk_risk_score)+"/100\n\n")

    output.insert(tk.END,"ORIGINAL APP MAIN INFO\n")
    output.insert(tk.END,"-----------------\n")
    output.insert(tk.END,"Folder Size: "+str(round(original_size,2))+" MB\n")
    output.insert(tk.END,"Total Files: "+str(original_total_files)+"\n")
    output.insert(tk.END,"Databases: "+str(original_db_count)+"\n")
    output.insert(tk.END,"Scripts: "+str(original_script_count)+"\n")
    output.insert(tk.END,"URLs Found: "+str(original_url_count)+"\n")
    output.insert(tk.END,"IPs Found: "+str(original_ip_count)+"\n")
    output.insert(tk.END,"Risk Score: "+str(original_risk_score)+"/100\n")

# ==========================
# LINE GRAPH
# ==========================

def show_graph():

    labels=["APK","Original"]

    scores=[apk_risk_score,original_risk_score]

    plt.plot(labels,scores,marker='o',linewidth=3,label="Risk Score")

    plt.title("APK vs Original Security Comparison")

    plt.ylabel("Risk Score")

    plt.xlabel("Application Type")

    plt.legend()

    plt.grid(True)

    plt.show()

# ==========================
# BUTTONS
# ==========================

scan_button=tk.Button(root,text="SCAN WEBSITE",font=("Arial",14,"bold"),bg="green",fg="white",width=20,command=scan_target)
scan_button.pack(pady=10)

apk_button=tk.Button(root,text="SCAN APK FILE",font=("Arial",14,"bold"),bg="red",fg="white",width=20,command=scan_apk)
apk_button.pack(pady=10)

original_button=tk.Button(root,text="SCAN ORIGINAL APP (DATA + OBB)",font=("Arial",14,"bold"),bg="orange",fg="white",width=25,command=scan_original_app)
original_button.pack(pady=10)

compare_button=tk.Button(root,text="COMPARE APK vs ORIGINAL",font=("Arial",14,"bold"),bg="blue",fg="white",width=25,command=compare_analysis)
compare_button.pack(pady=10)

graph_button=tk.Button(root,text="SHOW RISK GRAPH",font=("Arial",14,"bold"),bg="purple",fg="white",width=25,command=show_graph)
graph_button.pack(pady=10)

# ==========================
# OUTPUT WINDOW
# ==========================

output=scrolledtext.ScrolledText(root,width=110,height=30,font=("Consolas",10),bg="black",fg="white")
output.pack(pady=10)

# ==========================
# RUN GUI
# ==========================

root.mainloop()
