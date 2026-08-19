# Absolute Beginner's Guide: How to Start the Application

If you are new to coding, don't worry! This guide will take you step-by-step on exactly what to do, where to click, and what to type.

This application has two parts you need to run:
1. **The Backend** (the server that does the heavy lifting)
2. **The Frontend** (the visual webpage you interact with)

---

## Step 1: Open Your Terminal

A "Terminal" is a text-based window where you can type commands to your computer.

**How to open a terminal in VS Code:**
1. Look at the top menu bar in VS Code.
2. Click on **Terminal** -> **New Terminal**.
3. A new panel will open at the bottom of your screen. This is your command line!

---

## Step 2: Start the Backend Server

We need to start the backend server first. We will use the terminal you just opened.

**1. Go into the backend folder:**
Type the following command into your terminal and press **Enter**:
```powershell
cd "c:\Users\Work PC.DESKTOP-3L7JM27\Documents\ChromeOS\chromeos-connector-prototype\backend"
```
*(This tells your computer to "Change Directory" into the backend folder).*

**2. Download requirements (Only needed the first time):**
Type this and press **Enter**:
```powershell
go mod tidy
```

**3. Run the server:**
Type this and press **Enter**:
```powershell
go run .
```

**Success!** If it worked, you will see a message saying:
`chromeos connector mock backend listening on :8080`

**STOP HERE:** Leave this terminal window open and running. Do not close it!

---

## Step 3: Start the Frontend Application

Now we need to start the frontend webpage. 

**1. Open a SECOND terminal:**
- In VS Code, look at the Terminal panel at the bottom.
- Click the **"+" (plus)** icon on the right side of the terminal panel to open a *new*, second terminal.

**2. Go into the frontend folder:**
In this new terminal, type this and press **Enter**:
```powershell
cd "c:\Users\Work PC.DESKTOP-3L7JM27\Documents\ChromeOS\chromeos-connector-prototype\frontend"
```

**3. Start the frontend server:**
Type this and press **Enter**:
```powershell
python -m http.server 3000
```

**4. View the application:**
- Open your regular web browser (like Google Chrome or Edge).
- In the address bar at the top, type exactly: **http://localhost:3000**
- Press **Enter**. You should now see your application!

---

## Troubleshooting: "Address already in use" Error

Sometimes, when you try to run the server, you might get a scary red error saying `bind: address already in use`. 
This just means that your computer forgot to shut down the server from the last time you ran it, and it's still running invisibly in the background (holding onto port 8080 or 3000).

Here is exactly how to fix it in Windows:

**1. Find the invisible program:**
Open a new terminal (click the `+` icon) and type this, then press **Enter**:
```powershell
netstat -ano | findstr :8080
```
- You will see a line of text appear. 
- Look at the very **last number** on that line (for example, `12345`). This number is the "PID" (Process ID).

**2. Kill the invisible program:**
Now, type this command but replace `12345` with the number you just found, and press **Enter**:
```powershell
taskkill /PID 12345 /F
```
- It should say "SUCCESS: The process with PID ... has been terminated."

**3. Try again!**
Now you can go back up to **Step 2** and try running `go run .` again. It should work perfectly!
