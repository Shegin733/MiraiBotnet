# Mirai Botnet Detection Tool
In October 2016, the Mirai botnet launched a significant distributed denial of service (DDoS) attack on the domain name system provider Dyn, revealing the potential of Internet of Things (IoT) devices to be weaponized in large-scale cyberattacks.
Although DDoS attacks have existed since the early days of the internet, this incident highlighted how IoT devices could be harnessed to form botnets and disrupt major online services. 
The attack on Dyn resulted in widespread outages, temporarily taking down popular platforms like Twitter, Netflix, Spotify, GitHub, Airbnb, and more, underscoring the vulnerabilities in modern internet infrastructure.

https://github.com/user-attachments/assets/c6e4b109-8e9d-416f-b9b0-50b69c0b057a



## What's Inside?
1) A python tool is developed which identifies Mirai botnet based on the ip address,using machine learned patterns from the ip address earlier identified at attack scenarios,Decision Tree Classifier
   Algorithm  is used for model creation.[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/mirai_python_tool)
2) Smart IoT environment is created by using a flutter app(only works in emulater)[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/mirai_python_tool) and a wifi-enabled esp8266 microcontroller used to control light bulb.[⇗](https://github.com/Shegin733/MiraiBotnet/tree/master/iot/miraii)

## Botnet Detection 
The python tool has simple Tkinter framework,the tool is able to
- provide detailed report on network analysis 
- able to send Emails upon botnet detection
- capture live packets incoming and outgoing in a network and analyze it ,this operation is performed at an instance and may require further advanced programming for purpose of continous sniffing in a live environment
- Checks for already captured network PCAP files for presence of mirai botnet(Mirai presence pcap file is [ given in ](https://github.com/Shegin733/MiraiBotnet/blob/master/mirai_python_tool/MiraiTraffic.pcap)
- Downloads PDF of network analysis
- Send state of network to Firebase realtime database
## Simulated IoT Environment
The simulated IoT environment is created by a ESP8266 Microcontroller connected to a light bulb and buzzer,the 
microcontroller is able to recieve commands from app via Firebase realtime database system to turn on and off the bulb , buzzer will be activated  in presence of mirai so as to shut the effected IoT network,the buzzer will
not go off unless and until either the power system to IoT network is shut down or the threat alert from app is being mitigated via Firebase.
## Flutter Mobile App
The Flutter Mobile smart app is build for smart control of light,it's able to send commands to the IoT device so as to control light bulb.The  mobile app has authentication features with registration and login,
the app is able to recieve commands from python tool regarding network status and create alert based on it,on identifying potential threat of Mirai it activates the buzzer alarm and a warning notification is displayed.


# Mirai Botnet Detection — Setup Guide

This guide supplements the repository's existing `README.md`; it does not replace it. The project is an educational prototype that explores network-traffic analysis, a Decision Tree classifier, Firebase status reporting, a Flutter control/alert app, and an ESP8266 LED-and-buzzer simulation.

> **Safety and scope:** Use only the included sample PCAP files or traffic from a lab/network you own or have explicit permission to monitor. Do not use this prototype as a production security product or as proof that a device is safe. It is not a validated continuous monitoring system. Never connect experimental circuits directly to mains voltage.

## Project layout

```text
.
├── mirai_python_tool/        # Tkinter packet-analysis prototype and sample PCAPs
├── mirai_flutter_simulation/ # Flutter app for status, alerts, and LED control
├── iot/miraii/               # ESP8266 firmware for LED and buzzer control
├── LICENSE
└── README.md                 # Existing project overview
```

## Requirements

- Git
- Python 3.9+ recommended for the desktop analysis prototype
- Flutter SDK and a supported Android/iOS development toolchain for the app
- Arduino IDE (or compatible Arduino tooling) with ESP8266 board support for firmware
- A Firebase project for the app/device integration

The repository does not currently include a Python `requirements.txt`. Dependencies are listed in the relevant setup steps below.

## 1. Get the project

```bash
git clone https://github.com/Shegin733/MiraiBotnet.git
cd MiraiBotnet
```

## 2. Python packet-analysis prototype

### Create an environment and install dependencies

From the repository root:

```bash
python -m venv .venv
```

Activate it:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install the packages used by the analysis and optional model-training scripts:

```bash
python -m pip install --upgrade pip
python -m pip install numpy scapy reportlab firebase-admin scikit-learn pandas matplotlib
```

Tkinter is included with many Python distributions. On Debian/Ubuntu, if it is missing, install the system package with `sudo apt install python3-tk`. On Windows, use a Python installer that includes Tcl/Tk.

### Configure before running

The current Python scripts contain machine-specific paths and placeholder integrations. Before launching `mirai.py`:

1. Update the hard-coded model path in `mirai_python_tool/mirai.py` so it points to the repository's `mirai_python_tool/classifier.pkl` (or to your own trained model).
2. If using Firebase, configure the Firebase Realtime Database URL and a service-account JSON file for a Firebase project you control. Update the current placeholder path and URL in the script. Keep the service-account file out of Git.
3. If enabling email alerts, replace the placeholder mail settings with a secure configuration. Do not commit passwords, app passwords, API keys, or credentials. Prefer environment variables and a mail account intended for testing.
4. Check the code's assumptions about packet fields and classifier features against your chosen PCAP and model. This is an experimental prototype; the supplied classifier and feature handling should be validated before relying on its output.

The app/device integration expects Firebase Realtime Database values including `/Mirai`, `/LED`, and `/BUZ`. Configure database rules for a controlled test project; do not make a production database publicly writable.

### Run with a sample PCAP

From the repository root, launch the desktop application:

```bash
python mirai_python_tool/mirai.py
```

Choose **Upload PCAP File** and select one of the supplied `.pcap` files, such as `mirai_python_tool/sample.pcap` or `mirai_python_tool/MiraiTraffic.pcap`. The tool displays packet summaries and its prototype detection result; it can also generate a PDF report.

The **Live Packet Capture** option invokes packet sniffing and may require elevated operating-system permissions. Use it only on a device and network you own or are explicitly authorized to test. Prefer the sample-PCAP workflow for initial evaluation.

### Optional: retrain the Decision Tree

`mirai_python_tool/Dec_Tree.py` is an example training script. It expects a dataset CSV and currently includes a local machine-specific path. Before running it, edit the dataset path and verify the feature-column selection and target labels match your dataset. Run it from the `mirai_python_tool` directory so its output `classifier.pkl` is created there:

```bash
cd mirai_python_tool
python Dec_Tree.py
cd ..
```

Training is optional when using the checked-in model file. Do not interpret the script's reported score as real-world detection performance without a documented dataset, leakage-resistant evaluation, and representative independent test data.

## 3. Flutter app

Install Flutter and the Android or iOS toolchain using the official [Flutter installation guide](https://docs.flutter.dev/get-started/install). Then:

```bash
cd mirai_flutter_simulation
flutter doctor
flutter pub get
flutter run
```

For Firebase-backed functionality, create/configure a Firebase project for your own test deployment:

- Android: configure the app's package in Firebase and provide the matching `google-services.json` under `android/app/`.
- iOS: configure the iOS app and add its `GoogleService-Info.plist` to the iOS Runner project.
- Enable the Firebase Authentication method used by the app and configure Realtime Database.
- Set database rules for your test users and devices; avoid exposing the database to unauthenticated writes.

The Flutter app includes account screens, a status view that listens for the Mirai flag, LED control through Firebase, and an alert/buzzer status flow. Some project configuration is specific to the original development environment and may need adjustment before it runs with a new Firebase project or device.

## 4. ESP8266 LED and buzzer simulation

Open `iot/miraii/miraii.ino` in Arduino IDE.

1. Install ESP8266 board support using the official Espressif Arduino core instructions.
2. Install the Firebase client library required by the sketch and include its helper headers (`addons/TokenHelper.h` and `addons/RTDBHelper.h`) in the Arduino project as required by that library.
3. Set the ESP8266 board and serial port.
4. Configure the Wi-Fi SSID/password and Firebase API key/Realtime Database URL in the sketch for your own test environment. Keep real credentials out of commits.
5. Confirm the wiring matches the sketch: LED on GPIO 5 and buzzer on GPIO 15. Use suitable current-limiting and driver components for your hardware.
6. Upload the firmware and open Serial Monitor to check Wi-Fi/Firebase connection and status messages.

The firmware polls `/LED` and `/BUZ` and switches the corresponding outputs. Test with low-voltage components only; use properly rated, isolated hardware and qualified supervision for any higher-voltage loads.

## Data flow

1. The Python desktop tool reads a selected PCAP (or, when explicitly authorized, captures packets) and applies its current packet heuristics and saved classifier.
2. The Python tool writes a detection state to Firebase Realtime Database when configured.
3. The Flutter app reads the status and can update the LED state in Firebase.
4. The ESP8266 polls the database and controls the LED and buzzer outputs.

## Known limitations

- This is a learning/demo project, not a production IDS, endpoint security tool, or continuously validated Mirai detector.
- Python scripts contain placeholder credentials, database settings, email settings, and local paths that must be replaced before use.
- The training script expects a separate dataset and uses hard-coded feature indexes and a local CSV path.
- Model provenance, training data, thresholds, and independent performance evaluation are not fully documented.
- Firebase access rules and secrets must be configured securely for any deployment.
- The Flutter application and ESP8266 firmware depend on compatible Firebase configuration and database paths.

## Responsible use

Use this project for learning and authorized defensive testing. Work with provided PCAP samples or controlled lab data, protect any captured traffic because it can contain sensitive information, and obtain permission before monitoring a network. Treat detections as experimental signals that require independent verification.

## License

See [`LICENSE`](LICENSE) for license information.
