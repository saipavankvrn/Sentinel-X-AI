# 🛡️ Sentinel-X Cyber Threat Monitor

Sentinel-X is a fully automated, AI-driven cybersecurity SOC dashboard. It captures live network packets, runs them through an Isolation Forest machine learning model to detect anomalies, queries Google's Gemini AI to explain the threat in plain English, and finally uses your operating system's firewall (Windows Defender / iptables) to instantly block the attacker IP.

---

## ⚡ Quick Start (If already installed)

Open **3 separate terminal windows** and paste the following blocks of code to instantly boot your system:

**Terminal 1 (Backend Engine):**
```powershell
cd "C:\dummy\sentinal x\sentinel-x"
.\venv\Scripts\activate
cd backend
uvicorn main:app --reload
```

**Terminal 2 (React Dashboard):**
```powershell
cd "C:\dummy\sentinal x\sentinel-x\frontend"
npm run dev -- --port 5175
```

**Terminal 3 (Traffic Simulator):**
```powershell
cd "C:\dummy\sentinal x\sentinel-x"
.\venv\Scripts\activate
python simulate_attack.py
```

---

## 🚀 Complete Setup Guide (From Scratch)

Follow these steps if you are running this project for the very first time on a new computer.

### Step 1: Create a Python Virtual Environment

It is highly recommended to run this project inside an isolated virtual environment so the AI dependencies do not conflict with your computer's main Python installation.

1. Open your terminal (PowerShell or Command Prompt).
2. Navigate to the root directory of the project:
   ```powershell
   cd "C:\dummy\sentinal x\sentinel-x"
   ```
3. Create the virtual environment (named `venv`):
   ```powershell
   python -m venv venv
   ```
4. **Activate** the virtual environment:
   * **On Windows:**
     ```powershell
     .\venv\Scripts\activate
     ```
   * **On Linux/Mac:**
     ```bash
     source venv/bin/activate
     ```
   *(You should now see `(venv)` at the start of your terminal prompt!)*

### Step 2: Install Python Dependencies

With the virtual environment activated, install all the required Python libraries for the AI, Packet Sniffer, and Backend Server:

```powershell
pip install fastapi uvicorn pydantic scapy scikit-learn pandas google-generativeai requests
```

*(Note for Windows users: The live packet sniffer `scapy` requires **Npcap** to physically read your network card. If you install Wireshark on your computer, it comes with Npcap automatically).*

### Step 3: Install Frontend (React) Dependencies

We need to download the Node modules required to run the beautiful SOC Dashboard UI.

1. Open a new terminal and navigate to the frontend folder:
   ```powershell
   cd "C:\dummy\sentinal x\sentinel-x\frontend"
   ```
2. Install the packages using npm:
   ```powershell
   npm install
   ```

### Step 4: Train the AI Model (Run Once)

Before Sentinel-X can actually detect anomalies, the Machine Learning model needs to observe what "Normal" network traffic looks like on your machine.

1. Go back to your first terminal (make sure the `(venv)` tag is visibly activated).
2. Run the traffic collector for 10-15 seconds to gather a baseline `collected_traffic.csv` file:
   ```powershell
   python backend/traffic_collector.py
   ```
   *(Wait while it grabs packets, then stop it using `Ctrl+C`)*
3. Generate the actual AI model (`isolation_model.pkl`) using that data:
   ```powershell
   python ml/train_model.py
   ```
*(You only need to do this step once on a fresh install).*

---

## 💻 How to Run the Application

Once everything is installed successfully, you need **three separate terminal windows** to run the complete stack simultaneously.

### Terminal 1: Start the Backend API (FastAPI)
This server acts as the brain, processing the alerts and syncing math stats to the UI.
1. Open a new Terminal and activate your virtual environment:
   ```powershell
   cd "C:\dummy\sentinal x\sentinel-x"
   .\venv\Scripts\activate
   cd backend
   ```
2. Start the server:
   ```powershell
   uvicorn main:app --reload
   ```

### Terminal 2: Start the Security Dashboard (React)
This brings up the visual Matrix-style SOC monitoring grid!
1. Open a new Terminal.
2. Navigate to the frontend folder and start Vite (forcing port 5175 to avoid port conflicts with other apps on your PC):
   ```powershell
   cd "C:\dummy\sentinal x\sentinel-x\frontend"
   npm run dev -- --port 5175
   ```
3. Open your web browser and go to: **`http://localhost:5175`**

### Terminal 3: Start Capturing Traffic
Now that the UI and Backend are listening, you need to actually scan packets!

**Option A: The Simulator (For Testing without real threats)**
If you just want to see the dashboard light up with fake cyber-attacks and Gemini AI Explanations to verify the beautiful UI:
```powershell
cd "C:\dummy\sentinal x\sentinel-x"
.\venv\Scripts\activate
python simulate_attack.py
```

**Option B: The Real Packet Sniffer (Live Mitigation)**
If you want to actively monitor real Wi-Fi/Ethernet traffic and let the script physically alter your Windows Firewall to block real threats over the wire:
1. You **MUST** open the terminal app as **Administrator**.
2. Start the sniffer script:
```powershell
cd "C:\dummy\sentinal x\sentinel-x"
.\venv\Scripts\activate
python backend/packet_sniffer.py
```
"# Sentinal-x" 
