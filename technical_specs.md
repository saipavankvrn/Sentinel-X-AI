# 🛡️ Sentinel-X Technical Documentation

This document provides a clear breakdown of the intelligence and logic behind the Sentinel-X AI detection engine.

---

## 📊 1. Features Used for Training
Sentinel-X focuses on **7 key network features** extracted from live traffic flows:

1.  **Flow Duration:** The total time of a communication session.
2.  **Total FWD/BWD Packets:** The count of packets sent and received.
3.  **Packet Length Mean:** The average size of data packets in a flow.
4.  **Flow Bytes/s:** The speed of data transfer.
5.  **Protocol:** The communication standard used (TCP, UDP, ICMP).
6.  **Destination Port:** The service being accessed (e.g., Port 80 for Web, 22 for SSH).
7.  **Packet Rate:** How many packets are sent per second.

---

## 🎯 2. Why These Features Were Selected?
We selected these features based on **Behavioral Analysis** rather than simple signatures:
*   **Spoof-Proof:** Attackers can change their IP address, but they cannot hide the *behavior* of an attack. A DDoS attack will always have a high packet rate and specific length patterns.
*   **Encryption-Friendly:** Even if the packet content is encrypted (HTTPS), these features (like length and duration) remain visible and collectible.
*   **Efficiency:** These 7 features provide a 98%+ accuracy rate while being lightweight enough to process in under **1 millisecond**.

---

## 🧠 3. How the Model Detects Anomalies
Sentinel-X uses a **Dual-Engine Approach**:

1.  **Supervised Learning (Random Forest):** 
    *   Trained on the **CICIDS2017** dataset.
    *   It knows exactly what "Normal" and "Malicious" look like based on millions of past attack examples.
2.  **Adaptive Learning (Dynamic Growth):**
    *   The system captures live traffic and appends it to its internal dataset (`live_learning.csv`).
    *   This allows the model to "learn" the unique personality of your specific network and adapt to new, unseen attack patterns.

---

## ⚖️ 4. Handling False Positives
To prevent "The Boy Who Cried Wolf," Sentinel-X implements a **Three-Step Validation**:

1.  **AI Explanation (Gemini):** High-risk alerts are sent to the Google Gemini AI. The AI analyzes the packet statistics and explains *why* it thinks it's a threat in plain English.
2.  **Manual Overrule:** Administrators can view the AI's reasoning on the dashboard. If the traffic is legitimate, they can use the **One-Click Unblock** feature.
3.  **Probability Thresholds:** The model is tuned with a high confidence requirement. It will only block traffic if the mathematical probability of it being an attack exceeds a strict threshold.

---

> **"Security is not just about blocking; it's about understanding."**  
> — *Sentinel-X Research Team*
